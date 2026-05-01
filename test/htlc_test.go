package test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// 32-byte HTLC preimage + its HASH160 (RIPEMD160(SHA256(preimage)))
var (
	htlcPreimage = []byte{
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	}
	htlcPreimageHash = []byte{
		0x87, 0x39, 0xf4, 0x0e, 0xc4, 0xdb, 0xf5, 0x69, 0xdc, 0xb3,
		0x81, 0x34, 0xc6, 0xe7, 0x31, 0x09, 0x08, 0x56, 0x69, 0x81,
	}
)

const (
	contractAmount = int64(10_000)
	refundLocktime = uint32(500_000_000) // genesis timelock so always valid
)

// TestCovenantHTLC exercises an HTLC whose spending rules are enforced entirely
// by arkade covenants instead of receiver/sender signatures.
//
// The VTXO is owned by a 2-of-2 multisig (arkd signer + introspector-tweaked
// key) wrapped in a path-specific predicate closure. The introspector only
// signs once the arkade covenant on the spending tx passes.
//
// Shared arkade script — enforces output[i] goes to pkScript for the full input
// value (no fee deducted from the HTLC), where i is the current input index.
// Witness stack: empty.
// claim uses it to enforce the output goes to "receiver".
// refund uses it to enforce the output goes to "sender".
//
//	OP_PUSHCURRENTINPUTINDEX OP_DUP
//	OP_INSPECTOUTPUTSCRIPTPUBKEY
//	OP_1 OP_EQUALVERIFY            # force taproot
//	<receiver_or_sender_witness_program> OP_EQUALVERIFY
//	OP_INSPECTOUTPUTVALUE
//	OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE
//	OP_EQUAL
//
// Pinning the paid output to the current input index (rather than reading it
// from the witness) makes the script safe to compose: a taker claiming several
// HTLCs in one tx cannot point multiple inputs at a single output.
//
// Claim path — ConditionMultisigClosure with a HASH160 condition over the
// preimage. Condition witness: [preimage].
// Refund path — CLTVMultisigClosure with an absolute timelock.
//
// Neither path requires the receiver or sender to sign — the covenant acts
// in their place. Under the hood, the VTXO closures are :
// Claim: Introspector + Server + ConditionPreimage
// Refund: Introspector + Server + CLTV
func TestCovenantHTLC(t *testing.T) {
	ctx := t.Context()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)

	indexerSvc := setupIndexer(t)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	t.Run("claim", func(t *testing.T) {
		// who should receive from the claim
		receiverPkScript := randomP2TR(t)

		// script of the ConditionMultisigClosure
		preimageCondition, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_HASH160).
			AddData(htlcPreimageHash).
			AddOp(txscript.OP_EQUAL).
			Script()
		require.NoError(t, err)

		// claim must go to receiverPkScript
		arkadeScript := enforcePayTo(t, receiverPkScript)

		htlcVtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.ConditionMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{
							// server
							aliceAddr.Signer,
							// introspector
							arkade.ComputeArkadeScriptPublicKey(
								introspectorPubKey,
								arkade.ArkadeScriptHash(arkadeScript),
							),
						},
					},
					Condition: preimageCondition,
				},
			},
		}

		htlcInput := fund(
			t, ctx, alice, indexerSvc,
			aliceAddr.Signer, htlcVtxoScript, contractAmount,
		)

		// witness is empty — the script reads the output index from
		// OP_PUSHCURRENTINPUTINDEX.
		witness := wire.TxWitness{}
		// condition witness = [preimage].
		conditionWitness := wire.TxWitness{htlcPreimage}

		buildClaim := func(outputs []*wire.TxOut) (*psbt.Packet, []*psbt.Packet) {
			ptx, checkpoints, err := offchain.BuildTxs(
				[]offchain.VtxoInput{htlcInput}, outputs, checkpointScriptBytes,
			)
			require.NoError(t, err)

			require.NoError(t, txutils.SetArkPsbtField(
				ptx, 0, txutils.ConditionWitnessField, conditionWitness,
			))
			for _, cp := range checkpoints {
				require.NoError(t, txutils.SetArkPsbtField(
					cp, 0, txutils.ConditionWitnessField, conditionWitness,
				))
			}

			addIntrospectorPacket(t, ptx, []arkade.IntrospectorEntry{
				{Vin: 0, Script: arkadeScript, Witness: witness},
			})
			return ptx, checkpoints
		}

		submitAndExpectFailure := func(outputs []*wire.TxOut) {
			candidateTx, checkpoints := buildClaim(outputs)

			encodedTx, err := candidateTx.B64Encode()
			require.NoError(t, err)

			_, _, err = introspectorClient.SubmitTx(
				ctx, encodedTx, encodeCheckpoints(t, checkpoints),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to process transaction")
		}

		// Invalid: wrong destination at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount, PkScript: []byte{0x6a}}, // OP_RETURN
		})

		// Invalid: wrong amount at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount - 1, PkScript: receiverPkScript},
			{Value: 1, PkScript: randomP2TR(t)}, // need a change
		})

		// Valid: preimage revealed + right output
		validTx, validCheckpoints := buildClaim(
			[]*wire.TxOut{{Value: contractAmount, PkScript: receiverPkScript}},
		)

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)

		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(
			ctx, encodedValidTx, encodeCheckpoints(t, validCheckpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	})

	t.Run("claim_multiple", func(t *testing.T) {
		// A single taker claims several HTLCs in one ark tx. Each input
		// is paired with the output at the same index — pinned by
		// OP_PUSHCURRENTINPUTINDEX in the arkade script.
		const numHTLCs = 3

		receiverPkScript := randomP2TR(t)
		arkadeScript := enforcePayTo(t, receiverPkScript)
		arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

		preimages := make([][]byte, numHTLCs)
		htlcInputs := make([]offchain.VtxoInput, numHTLCs)

		for i := range numHTLCs {
			preimage := make([]byte, 32)
			for j := range preimage {
				preimage[j] = byte(i + 1)
			}
			preimages[i] = preimage

			preimageCondition, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(btcutil.Hash160(preimage)).
				AddOp(txscript.OP_EQUAL).
				Script()
			require.NoError(t, err)

			htlcVtxoScript := script.TapscriptsVtxoScript{
				Closures: []script.Closure{
					&script.ConditionMultisigClosure{
						MultisigClosure: script.MultisigClosure{
							PubKeys: []*btcec.PublicKey{
								aliceAddr.Signer,
								arkade.ComputeArkadeScriptPublicKey(
									introspectorPubKey, arkadeScriptHash,
								),
							},
						},
						Condition: preimageCondition,
					},
				},
			}

			htlcInputs[i] = fund(
				t, ctx, alice, indexerSvc,
				aliceAddr.Signer, htlcVtxoScript, contractAmount,
			)
		}

		outputs := make([]*wire.TxOut, numHTLCs)
		for i := range numHTLCs {
			outputs[i] = &wire.TxOut{Value: contractAmount, PkScript: receiverPkScript}
		}

		ptx, checkpoints, err := offchain.BuildTxs(
			htlcInputs, outputs, checkpointScriptBytes,
		)
		require.NoError(t, err)

		// One condition witness per input on the ark tx; one per
		// checkpoint (each checkpoint has a single input).
		entries := make([]arkade.IntrospectorEntry, numHTLCs)
		for i, preimage := range preimages {
			require.NoError(t, txutils.SetArkPsbtField(
				ptx, i, txutils.ConditionWitnessField, wire.TxWitness{preimage},
			))
			entries[i] = arkade.IntrospectorEntry{
				Vin:     uint16(i),
				Script:  arkadeScript,
				Witness: wire.TxWitness{},
			}
		}
		for i, cp := range checkpoints {
			require.NoError(t, txutils.SetArkPsbtField(
				cp, 0, txutils.ConditionWitnessField, wire.TxWitness{preimages[i]},
			))
		}

		addIntrospectorPacket(t, ptx, entries)

		vouts := make([]uint32, numHTLCs)
		for i := range numHTLCs {
			vouts[i] = uint32(i)
		}
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, ptx, vouts...)

		encodedTx, err := ptx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(
			ctx, encodedTx, encodeCheckpoints(t, checkpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	})

	t.Run("refund", func(t *testing.T) {
		// who should receive from the refund
		senderPkScript := randomP2TR(t)

		// refund must go to senderPkScript
		arkadeScript := enforcePayTo(t, senderPkScript)

		htlcVtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.CLTVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{
							// server
							aliceAddr.Signer,
							// introspector
							arkade.ComputeArkadeScriptPublicKey(
								introspectorPubKey,
								arkade.ArkadeScriptHash(arkadeScript),
							),
						},
					},
					Locktime: arklib.AbsoluteLocktime(refundLocktime),
				},
			},
		}

		htlcInput := fund(
			t, ctx, alice, indexerSvc,
			aliceAddr.Signer, htlcVtxoScript, contractAmount,
		)

		// witness is empty — the script reads the output index from
		// OP_PUSHCURRENTINPUTINDEX.
		witness := wire.TxWitness{}

		submitAndExpectFailure := func(outputs []*wire.TxOut) {
			candidateTx, checkpoints, err := offchain.BuildTxs(
				[]offchain.VtxoInput{htlcInput}, outputs, checkpointScriptBytes,
			)
			require.NoError(t, err)

			addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
				{Vin: 0, Script: arkadeScript, Witness: witness},
			})

			encodedTx, err := candidateTx.B64Encode()
			require.NoError(t, err)

			_, _, err = introspectorClient.SubmitTx(
				ctx, encodedTx, encodeCheckpoints(t, checkpoints),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to process transaction")
		}

		// Invalid: wrong destination at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount, PkScript: []byte{0x6a}}, // OP_RETURN
		})

		// Invalid: wrong amount at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount - 1, PkScript: senderPkScript},
			{Value: 1, PkScript: randomP2TR(t)},
		})

		// Valid: CLTV satisfied + right output
		validTx, validCheckpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{htlcInput},
			[]*wire.TxOut{{Value: contractAmount, PkScript: senderPkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)

		addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: arkadeScript, Witness: witness},
		})

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)

		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(
			ctx, encodedValidTx, encodeCheckpoints(t, validCheckpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	})
}

// enforcePayTo builds an arkade script that asserts the output at the
// current input index goes to pkScript for exactly the current input's value.
// The witness stack is empty.
func enforcePayTo(t *testing.T, pkScript []byte) []byte {
	t.Helper()

	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_DUP).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddData(pkScript[2:]).        // witness program
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return s
}

// randomP2TR returns a fresh P2TR scriptPubKey. Used for destinations where
// the identity is irrelevant to the test.
func randomP2TR(t *testing.T) []byte {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := txscript.PayToTaprootScript(priv.PubKey())
	require.NoError(t, err)

	return pkScript
}

// fund locks contractAmount into a VTXO with the given script and
// returns the spend input for its forfeit leaf.
func fund(
	t *testing.T,
	ctx context.Context,
	alice arksdk.ArkClient,
	indexerSvc indexer.Indexer,
	serverSigner *btcec.PublicKey,
	htlcVtxoScript script.TapscriptsVtxoScript,
	contractAmount int64,
) offchain.VtxoInput {
	t.Helper()

	htlcTapKey, _, err := htlcVtxoScript.TapTree()
	require.NoError(t, err)

	htlcAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: htlcTapKey,
		Signer:     serverSigner,
	}
	htlcAddrStr, err := htlcAddr.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{
		{To: htlcAddrStr, Amount: uint64(contractAmount)},
	})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	htlcTapscript := onlyForfeitScript(t, htlcVtxoScript)
	htlcVout, htlcOutput := findTaprootOutput(t, fundingPtx.UnsignedTx, htlcTapKey)
	require.Equal(t, contractAmount, htlcOutput.Value)

	return vtxoInputFromScriptOutput(
		t, fundingPtx.UnsignedTx, htlcVout, htlcVtxoScript, htlcTapscript,
	)
}
