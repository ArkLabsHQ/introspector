package test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestCounterContractBatchContinuation pins down the current inability to
// batch-continue a contract VTXO.
//
// Semantics: a batch swap is a passive move of a VTXO into the next batch —
// NOT a contract call. arkd is expected to COPY the creating tx's
// introspector / state packets onto the new leaf tx so the contract state is
// preserved as-is; no transition is performed. The intent proof therefore
// carries the same state as the deploy tx (counter=0).
//
// Today this is not possible:
//  1. arkd drops every extension packet except the asset packet (type 0x00)
//     when building the leaf tx, so state would be lost even if signing
//     succeeded. Tracked in https://github.com/arkade-os/arkd/issues/1017.
//  2. The only way to obtain the introspector's arkade-tweaked signature on
//     the intent proof is SubmitIntent, which executes the arkade script.
//     The counter contract only authorizes increment-by-1 (not preservation),
//     so the script rejects the preservation-intent proof.
//
// The test asserts (2): SubmitIntent fails because the counter script cannot
// authorize a batch move that preserves state.
//
// To make batch continuation work, the introspector needs a signing path that
// does NOT execute the contract script — either an extra option on
// SubmitIntent (e.g. a "batch continuation" flag that skips script execution
// and signs the arkade-tweaked key for a state-preserving proof) or a new
// dedicated RPC for batch-continuation intents. Both require arkd to also
// carry the introspector / state packets across batches (issue #1017).
//
// TODO: flip this test to a success path once arkd carries custom extension
// packets across batches AND the introspector exposes a batch-continuation
// signing path (extra SubmitIntent option or new RPC) that does not execute
// the contract script.
func TestCounterContractBatchContinuation(t *testing.T) {
	ctx := t.Context()

	alice, grpcClient := setupArkSDK(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 20000)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	infos, err := grpcClient.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)

	// =========================================================================
	// Phase 1: Deploy the counter at counter=0, reusing the helpers from
	// counter_contract_test.go.
	// =========================================================================

	// The counter VTXO must carry a CSV exit leaf alongside the arkade
	// closure: arkd rejects batch forfeits of VTXOs that have no exit leaf
	// (INVALID_VTXO_SCRIPT / "no exit leaf"). The exit path is never taken in
	// this test — the CSV key is a throwaway.
	exitKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	counterArkadeScript := counterContractArkadeScript(t)
	counterVtxoScript := createArkadeVtxoScriptWithExit(
		aliceAddr.Signer,
		introspectorPubKey,
		exitKey.PubKey(),
		arkade.ArkadeScriptHash(counterArkadeScript),
	)
	counterTapscript := onlyForfeitScript(t, counterVtxoScript)
	counterDeployPkScript := p2trScriptForVtxoScript(t, counterVtxoScript)

	deployArkadeScript := counterDeployArkadeScript(t, counterDeployPkScript)
	stagingVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(deployArkadeScript),
	)
	stagingTapscript := onlyForfeitScript(t, stagingVtxoScript)
	stagingTapKey, _, err := stagingVtxoScript.TapTree()
	require.NoError(t, err)

	stagingAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: stagingTapKey,
		Signer:     aliceAddr.Signer,
	}
	stagingAddr, err := stagingAddress.EncodeV0()
	require.NoError(t, err)

	stagingTxid, err := alice.SendOffChain(
		ctx,
		[]types.Receiver{{To: stagingAddr, Amount: 20000}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, stagingTxid)

	stagingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{stagingTxid})
	require.NoError(t, err)
	require.Len(t, stagingTxs.Txs, 1)

	stagingPtx, err := psbt.NewFromRawBytes(strings.NewReader(stagingTxs.Txs[0]), true)
	require.NoError(t, err)

	stagingOutputIndex, stagingOutput := findTaprootOutput(t, stagingPtx.UnsignedTx, stagingTapKey)
	stagingInput := vtxoInputFromScriptOutput(
		t,
		stagingPtx.UnsignedTx,
		stagingOutputIndex,
		stagingVtxoScript,
		stagingTapscript,
	)

	encodeCheckpoints := func(checkpoints []*psbt.Packet) []string {
		encoded := make([]string, 0, len(checkpoints))
		for _, c := range checkpoints {
			s, err := c.B64Encode()
			require.NoError(t, err)
			encoded = append(encoded, s)
		}
		return encoded
	}

	deployTx, deployCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{stagingInput},
		[]*wire.TxOut{{Value: stagingOutput.Value, PkScript: counterDeployPkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)
	addCounterPacket(t, deployTx, 0)
	addIntrospectorPacket(t, deployTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: deployArkadeScript},
	})
	require.NoError(t, executeArkadeScripts(t, deployTx, deployCheckpoints, introspectorPubKey))

	encodedDeployTx, err := deployTx.B64Encode()
	require.NoError(t, err)
	_, _, err = introspectorClient.SubmitTx(
		ctx, encodedDeployTx, encodeCheckpoints(deployCheckpoints),
	)
	require.NoError(t, err)

	// =========================================================================
	// Phase 2: Attempt to batch-continue the counter by preserving state.
	//
	// The intent proof spends the counter VTXO and outputs the same amount
	// back to the same counter contract script. The counter packet carries
	// the SAME value as on the deploy tx (counter=0) — no increment, because
	// a batch swap is not a contract call.
	// =========================================================================

	counterVtxoAmount := stagingOutput.Value
	counterOutpoint := &wire.OutPoint{
		Hash:  deployTx.UnsignedTx.TxHash(),
		Index: 0,
	}
	counterWitnessUtxo := &wire.TxOut{
		Value:    counterVtxoAmount,
		PkScript: counterDeployPkScript,
	}

	cosignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerSession := tree.NewTreeSignerSession(cosignerKey)

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: nil,
		ExpireAt:             0,
		ValidAt:              0,
		CosignersPublicKeys:  []string{signerSession.GetPublicKey()},
	}.Encode()
	require.NoError(t, err)

	intentProof, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint:    counterOutpoint,
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: counterWitnessUtxo,
			},
		},
		[]*wire.TxOut{
			{
				Value:    counterVtxoAmount,
				PkScript: counterDeployPkScript,
			},
		},
	)
	require.NoError(t, err)

	_, counterTapTree, err := counterVtxoScript.TapTree()
	require.NoError(t, err)

	counterMerkleProof, err := counterTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(counterTapscript).TapHash(),
	)
	require.NoError(t, err)

	counterCtrlBlock, err := txscript.ParseControlBlock(counterMerkleProof.ControlBlock)
	require.NoError(t, err)
	counterCtrlBlockBytes, err := counterCtrlBlock.ToBytes()
	require.NoError(t, err)

	counterRevealedTapscripts, err := counterVtxoScript.Encode()
	require.NoError(t, err)
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(counterRevealedTapscripts)
	require.NoError(t, err)

	tapLeafScript := []*psbt.TaprootTapLeafScript{
		{
			LeafVersion:  txscript.BaseLeafVersion,
			ControlBlock: counterCtrlBlockBytes,
			Script:       counterMerkleProof.Script,
		},
	}
	intentProof.Inputs[0].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[1].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[0].Unknowns = append(intentProof.Inputs[0].Unknowns, taptreeField)
	intentProof.Inputs[1].Unknowns = append(intentProof.Inputs[1].Unknowns, taptreeField)

	intentPtx := &intentProof.Packet

	// Preserve the existing counter state: same value (0) as on the deploy
	// tx. Point the introspector packet at input 1 (input 0 is the fake
	// message input from intent.New).
	addCounterPacket(t, intentPtx, 0)
	addIntrospectorPacket(t, intentPtx, []arkade.IntrospectorEntry{
		{Vin: 1, Script: counterArkadeScript},
	})

	// OP_INSPECTINPUTPACKET on input 1 needs the deploy tx as the previous
	// ark tx to read the counter=0 packet.
	require.NoError(t, txutils.SetArkPsbtField(
		intentPtx, 1, arkade.PrevoutTxField, *deployTx.UnsignedTx,
	))

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	// SubmitIntent executes the counter arkade script against the intent
	// proof. The script only authorizes counter_new = counter_prev + 1, so
	// a preservation proof (counter=0 in, counter=0 out) fails. There is no
	// other way to obtain the arkade-tweaked signature today, so batch
	// continuation of this contract is not possible.
	_, err = introspectorClient.SubmitIntent(
		ctx, introspectorclient.Intent{
			Proof:   encodedIntentProof,
			Message: message,
		},
	)
	require.Error(t, err,
		"expected SubmitIntent to fail: the counter arkade script demands "+
			"increment, but batch continuation preserves state")
}

// createArkadeVtxoScriptWithExit returns a VTXO script with a 2-of-2 arkade
// forfeit closure (server signer + arkade-tweaked introspector) plus a CSV
// exit closure owned by exitOwner. The CSV exit is required so arkd accepts
// the VTXO as forfeitable in a batch.
func createArkadeVtxoScriptWithExit(
	serverSigner *btcec.PublicKey,
	introspectorPubKey *btcec.PublicKey,
	exitOwner *btcec.PublicKey,
	arkadeScriptHash []byte,
) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					serverSigner,
					arkade.ComputeArkadeScriptPublicKey(introspectorPubKey, arkadeScriptHash),
				},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{exitOwner},
				},
				Locktime: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeSecond,
					Value: 512 * 10,
				},
			},
		},
	}
}
