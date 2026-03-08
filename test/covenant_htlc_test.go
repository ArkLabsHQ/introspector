package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"context"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

// serializeWitness serializes stack items using Bitcoin's witness encoding:
// varint(count) || [varint(len) || data]...
func serializeWitness(items [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	err := psbt.WriteTxWitness(&buf, items)
	return buf.Bytes(), err
}

// TestCovenantHTLCClaim tests the covenant HTLC claim path where the receiver
// does NOT sign — only the preimage is needed. The Arkade script enforces that
// the output goes to the receiver's address with the correct amount.
//
// This mirrors fulmine's VHTLC TestVHTLC e2e test but uses introspection
// opcodes instead of receiver signatures for the claim path.
//
// Spending paths tested:
//  1. Covenant claim (invalid — wrong address): introspector rejects
//  2. Covenant claim (valid — correct output): introspector signs, no receiver sig needed
func TestCovenantHTLCClaim(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	// --- Receiver key (Bob) — NOT used for signing the claim ---
	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobPubKey := bobPrivKey.PubKey()
	bobPkScript, err := txscript.PayToTaprootScript(bobPubKey)
	require.NoError(t, err)
	bobWitnessProgram := bobPkScript[2:] // strip OP_1 + OP_DATA_32

	// --- Fund Alice ---
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)

	// --- Preimage setup (matches fulmine's random preimage pattern) ---
	preimage := bytes.Repeat([]byte{0x42}, 32)
	sha := sha256.Sum256(preimage)
	r := ripemd160.New()
	r.Write(sha[:])
	preimageHash := r.Sum(nil) // RIPEMD160(SHA256(preimage))

	// --- Constants ---
	const sendAmount = 10000
	const claimAmount = 10000

	claimAmountLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(claimAmountLE, uint64(claimAmount))

	// --- Build covenant claim Arkade script ---
	// Witness stack (bottom→top): <output_index> <preimage>
	// Script pops preimage first (OP_HASH160), then uses output_index twice (OP_DUP)
	arkadeScript, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_HASH160).
		AddData(preimageHash).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_DUP).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(bobWitnessProgram).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(claimAmountLE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// --- Introspector client ---
	introspectorClient, publicKey, connIntrospector := setupIntrospectorClient(t, ctx)
	defer connIntrospector.Close()

	// --- VTXO with Arkade closure ---
	// MultisigClosure contains: Bob, Alice's signer, and introspector tweaked key
	// This matches fulmine's ClaimClosure pattern but replaces ConditionMultisigClosure
	// with an Arkade-script-backed MultisigClosure
	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, aliceAddr.Signer, publicKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	htlcAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscriptObj := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	htlcAddrStr, err := htlcAddr.EncodeV0()
	require.NoError(t, err)

	// --- Alice sends to covenant HTLC ---
	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: htlcAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	// --- Find HTLC output in funding tx ---
	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var htlcOutput *wire.TxOut
	var htlcOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(htlcAddr.VtxoTapKey)) {
			htlcOutput = out
			htlcOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, htlcOutput)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  redeemPtx.UnsignedTx.TxHash(),
			Index: htlcOutputIndex,
		},
		Tapscript:          tapscriptObj,
		Amount:             htlcOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscript)},
	}

	// --- Serialize witness: [output_index=0, preimage] ---
	witnessBytes, err := serializeWitness([][]byte{{}, preimage})
	require.NoError(t, err)

	// ========================================
	// CASE 1: Invalid — wrong output address
	// ========================================
	invalidAddrTx, invalidAddrCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: claimAmount, PkScript: []byte{0x6a}}, // OP_RETURN, wrong address
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, invalidAddrTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: witnessBytes},
	})

	encodedInvalidAddrTx, err := invalidAddrTx.B64Encode()
	require.NoError(t, err)

	encodedInvalidAddrCheckpoints := make([]string, 0, len(invalidAddrCheckpoints))
	for _, cp := range invalidAddrCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedInvalidAddrCheckpoints = append(encodedInvalidAddrCheckpoints, encoded)
	}

	// No Bob wallet signing — submit directly to introspector
	_, _, err = introspectorClient.SubmitTx(ctx, encodedInvalidAddrTx, encodedInvalidAddrCheckpoints)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process transaction")

	// ========================================
	// CASE 2: Valid — covenant claim with correct output
	// ========================================
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: claimAmount, PkScript: bobPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: witnessBytes},
	})

	encodedValidTx, err := validTx.B64Encode()
	require.NoError(t, err)

	encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedValidCheckpoints = append(encodedValidCheckpoints, encoded)
	}

	// Submit to introspector — no Bob signing needed!
	signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(
		ctx, encodedValidTx, encodedValidCheckpoints,
	)
	require.NoError(t, err)

	// Submit to server
	txid, _, signedByServerCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedByServerCheckpoints))
	for i, checkpoint := range signedByServerCheckpoints {
		byInterceptorCheckpointPtx, err := psbt.NewFromRawBytes(
			strings.NewReader(signedByIntrospectorCheckpoints[i]), true,
		)
		require.NoError(t, err)

		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		require.NoError(t, err)

		checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
			checkpointPtx.Inputs[0].TaprootScriptSpendSig,
			byInterceptorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
		)

		finalCheckpoint, err := checkpointPtx.B64Encode()
		require.NoError(t, err)

		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, txid, finalCheckpoints)
	require.NoError(t, err)
}

// TestCovenantHTLCFullTapTree tests that a covenant HTLC can be constructed
// with all 6 spending paths (matching fulmine's VHTLC structure):
//  1. Covenant Claim — Arkade script (preimage + introspection, no receiver sig)
//  2. Traditional Claim — ConditionMultisigClosure (preimage + receiver + server)
//  3. Covenant Refund — Arkade script (timelock + introspection, no sender sig)
//  4. Traditional Refund — MultisigClosure (sender + receiver + server)
//  5. Refund Without Receiver — CLTVMultisigClosure (sender + server + CLTV)
//  6. Unilateral Claim — ConditionCSVMultisigClosure (preimage + receiver + CSV)
//
// This test validates the tap tree construction without requiring a running stack.
func TestCovenantHTLCFullTapTree(t *testing.T) {
	// --- Key setup ---
	senderPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	senderPubKey := senderPrivKey.PubKey()

	receiverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	receiverPubKey := receiverPrivKey.PubKey()

	serverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKey := serverPrivKey.PubKey()

	introspectorPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	introspectorPubKey := introspectorPrivKey.PubKey()

	// --- Preimage ---
	preimage := bytes.Repeat([]byte{0x42}, 32)
	sha := sha256.Sum256(preimage)
	r := ripemd160.New()
	r.Write(sha[:])
	preimageHash := r.Sum(nil)

	// --- Receiver output params ---
	receiverPkScript, err := txscript.PayToTaprootScript(receiverPubKey)
	require.NoError(t, err)

	senderPkScript, err := txscript.PayToTaprootScript(senderPubKey)
	require.NoError(t, err)

	const claimAmount = 10000
	claimAmountLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(claimAmountLE, uint64(claimAmount))

	// --- Preimage condition script (for traditional claim paths) ---
	preimageConditionScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// --- Leaf 1: Covenant Claim (Arkade script) ---
	covenantClaimScript, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_HASH160).
		AddData(preimageHash).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_DUP).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(receiverPkScript[2:]).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(claimAmountLE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	covenantClaimTweakedKey := arkade.ComputeArkadeScriptPublicKey(
		introspectorPubKey, arkade.ArkadeScriptHash(covenantClaimScript),
	)

	// --- Leaf 3: Covenant Refund (Arkade script) ---
	const refundLocktime int64 = 500000
	covenantRefundScript, err := txscript.NewScriptBuilder().
		AddInt64(refundLocktime).
		AddOp(arkade.OP_CHECKLOCKTIMEVERIFY).
		AddOp(arkade.OP_DROP).
		AddOp(arkade.OP_DUP).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(senderPkScript[2:]).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(claimAmountLE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	covenantRefundTweakedKey := arkade.ComputeArkadeScriptPublicKey(
		introspectorPubKey, arkade.ArkadeScriptHash(covenantRefundScript),
	)

	// --- Build full tap tree with all 6 closures ---
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			// Leaf 1: Covenant Claim — server + introspector (tweaked with claim script)
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{serverPubKey, covenantClaimTweakedKey},
			},
			// Leaf 2: Traditional Claim — receiver + server + preimage condition
			&script.ConditionMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{receiverPubKey, serverPubKey},
				},
				Condition: preimageConditionScript,
			},
			// Leaf 3: Covenant Refund — server + introspector (tweaked with refund script)
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{serverPubKey, covenantRefundTweakedKey},
			},
			// Leaf 4: Traditional Refund — sender + receiver + server
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{senderPubKey, receiverPubKey, serverPubKey},
			},
			// Leaf 5: Refund Without Receiver — sender + server + CLTV
			&script.CLTVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{senderPubKey, serverPubKey},
				},
				Locktime: arklib.AbsoluteLocktime(refundLocktime),
			},
			// Leaf 6: Unilateral Claim — receiver + preimage + CSV delay
			&script.ConditionCSVMultisigClosure{
				CSVMultisigClosure: script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{receiverPubKey},
					},
					Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
				},
				Condition: preimageConditionScript,
			},
		},
	}

	// --- Verify tap tree builds successfully ---
	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	require.NotNil(t, vtxoTapKey)
	require.NotNil(t, vtxoTapTree)

	// --- Verify each closure produces a valid tapscript ---
	for i, closure := range vtxoScript.Closures {
		closureScript, err := closure.Script()
		require.NoError(t, err, "closure %d failed to produce script", i)
		require.NotEmpty(t, closureScript, "closure %d produced empty script", i)

		// Verify each closure can be found in the tap tree
		leaf := txscript.NewBaseTapLeaf(closureScript)
		proof, err := vtxoTapTree.GetTaprootMerkleProof(leaf.TapHash())
		require.NoError(t, err, "closure %d not found in tap tree", i)
		require.NotNil(t, proof, "closure %d has nil proof", i)
	}

	// --- Verify forfeit closures are available ---
	forfeitClosures := vtxoScript.ForfeitClosures()
	require.NotEmpty(t, forfeitClosures)
}
