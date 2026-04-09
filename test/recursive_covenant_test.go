package test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"context"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestRecursivePolicy enforces a recursive policy VTXO for Bob:
// - output 0 can pay anyone as long as amount is < 1000 sats
// - output 1 must carry the change back to Bob's policy scriptPubKey
func TestRecursivePolicy(t *testing.T) {
	ctx := context.Background()

	alice, _, alicePubKey, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcBob.Close()
	})

	const (
		policyAmount     = int64(20000)
		maxAllowedOutput = int64(1000)
	)

	// Fund Alice so she can send to Bob's policy VTXOs.
	_ = fundAndSettleAlice(t, ctx, alice, 2*policyAmount)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)

	bobAddr, err := arklib.DecodeAddressV0(bobOffchainAddr)
	require.NoError(t, err)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	arkadeScript, err := txscript.NewScriptBuilder().
		// For simplicity, restrict to a single input
		AddOp(arkade.OP_INSPECTNUMINPUTS).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Output 0 value must be <= 1000 sats.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(uint64LE(uint64(maxAllowedOutput + 1))).
		AddOp(arkade.OP_LESSTHAN64).
		AddOp(arkade.OP_VERIFY).
		// Output 1 must match input scriptPubKey (recursive covenant).
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddOp(arkade.OP_EQUALVERIFY).
		// Output 1 value must be the input value - Output 0 value
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_SUB64).
		AddOp(arkade.OP_VERIFY). // check & pop the overflow flag
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	policyVtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey,
		bobAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	policyTapKey, policyTapTree, err := policyVtxoScript.TapTree()
	require.NoError(t, err)

	policyAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: policyTapKey,
		Signer:     bobAddr.Signer,
	}

	policyAddrStr, err := policyAddr.EncodeV0()
	require.NoError(t, err)

	// fund 2 policy VTXOs in order to test multi-input rejection
	fundingTxid, err := alice.SendOffChain(
		ctx,
		[]types.Receiver{
			{To: policyAddrStr, Amount: uint64(policyAmount)},
			{To: policyAddrStr, Amount: uint64(policyAmount)},
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	indexerSvc := setupIndexer(t)

	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxs)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	var policyOutputs []*wire.TxOut
	var policyOutputIndexes []uint32
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(policyAddr.VtxoTapKey)) {
			policyOutputs = append(policyOutputs, out)
			policyOutputIndexes = append(policyOutputIndexes, uint32(i))
		}
	}
	require.GreaterOrEqual(t, len(policyOutputs), 2)
	policyOutput := policyOutputs[0]
	policyOutputIndex := policyOutputIndexes[0]
	policyOutput2 := policyOutputs[1]
	policyOutputIndex2 := policyOutputIndexes[1]

	closure := policyVtxoScript.ForfeitClosures()[0]
	policyTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := policyTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(policyTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: policyOutputIndex,
		},
		Tapscript:          tapscript,
		Amount:             policyOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(policyTapscript)},
	}
	vtxoInput2 := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: policyOutputIndex2,
		},
		Tapscript:          tapscript,
		Amount:             policyOutput2.Value,
		RevealedTapscripts: []string{hex.EncodeToString(policyTapscript)},
	}

	inputPkScript, err := checkpointInputPkScript(vtxoInput, checkpointScriptBytes)
	require.NoError(t, err)
	inputPkScript2, err := checkpointInputPkScript(vtxoInput2, checkpointScriptBytes)
	require.NoError(t, err)

	carolPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	carolPkScript, err := txscript.PayToTaprootScript(carolPrivKey.PubKey())
	require.NoError(t, err)

	alicePkScript, err := txscript.PayToTaprootScript(alicePubKey)
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	submitAndFinalize := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.NoError(t, err)

		txid, _, signedByServerCheckpoints, err := grpcBob.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.NoError(t, err)

		finalCheckpoints := make([]string, 0, len(signedByServerCheckpoints))
		for i, checkpoint := range signedByServerCheckpoints {
			finalCheckpoint, err := bobWallet.SignTransaction(ctx, explorer, checkpoint)
			require.NoError(t, err)

			introspectorCheckpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedByIntrospectorCheckpoints[i]), true)
			require.NoError(t, err)

			checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalCheckpoint), true)
			require.NoError(t, err)

			checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
				checkpointPtx.Inputs[0].TaprootScriptSpendSig,
				introspectorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
			)

			finalCheckpoint, err = checkpointPtx.B64Encode()
			require.NoError(t, err)

			finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
		}

		err = grpcBob.FinalizeTx(ctx, txid, finalCheckpoints)
		require.NoError(t, err)
	}

	vtxoInputFromOutput := func(prevTx *wire.MsgTx, outIndex uint32) offchain.VtxoInput {
		signerUnrollScriptClosure := &script.CSVMultisigClosure{}
		valid, err := signerUnrollScriptClosure.Decode(checkpointScriptBytes)
		require.NoError(t, err)
		require.True(t, valid)

		collaborativeClosure, err := script.DecodeClosure(policyTapscript)
		require.NoError(t, err)

		checkpointVtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{signerUnrollScriptClosure, collaborativeClosure},
		}

		_, checkpointTapTree, err := checkpointVtxoScript.TapTree()
		require.NoError(t, err)

		checkpointMerkleProof, err := checkpointTapTree.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(policyTapscript).TapHash(),
		)
		require.NoError(t, err)

		checkpointCtrlBlock, err := txscript.ParseControlBlock(checkpointMerkleProof.ControlBlock)
		require.NoError(t, err)

		revealedCheckpointTapscripts, err := checkpointVtxoScript.Encode()
		require.NoError(t, err)

		return offchain.VtxoInput{
			Outpoint: &wire.OutPoint{Hash: prevTx.TxHash(), Index: outIndex},
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   checkpointCtrlBlock,
				RevealedScript: checkpointMerkleProof.Script,
			},
			Amount:             prevTx.TxOut[outIndex].Value,
			RevealedTapscripts: revealedCheckpointTapscripts,
		}
	}

	submitAndExpectFailure := func(inputs []offchain.VtxoInput, outputs []*wire.TxOut) {
		candidateTx, checkpoints, err := offchain.BuildTxs(
			inputs,
			outputs,
			checkpointScriptBytes,
		)
		require.NoError(t, err)

		entries := make([]arkade.IntrospectorEntry, 0, len(inputs))
		for i := range inputs {
			entries = append(entries, arkade.IntrospectorEntry{Vin: uint16(i), Script: arkadeScript})
		}

		addIntrospectorPacket(t, candidateTx, entries)

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	// Invalid: policy script requires exactly one input.
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput, vtxoInput2}, []*wire.TxOut{
		{Value: maxAllowedOutput, PkScript: carolPkScript},
		{Value: policyOutput.Value - maxAllowedOutput, PkScript: inputPkScript},
		{Value: policyOutput2.Value, PkScript: inputPkScript2},
	})

	// Invalid: recipient amount is not <= 1000.
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput}, []*wire.TxOut{
		{Value: maxAllowedOutput + 1, PkScript: carolPkScript},
		{Value: policyOutput.Value - int64(maxAllowedOutput+1), PkScript: inputPkScript},
	})

	// Invalid: recursive output does not receive the full remainder
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput}, []*wire.TxOut{
		{Value: maxAllowedOutput, PkScript: carolPkScript},
		{Value: policyOutput.Value - maxAllowedOutput - 1, PkScript: inputPkScript},
		{Value: 1, PkScript: carolPkScript},
	})

	// Invalid: output 1 does not return to the policy scriptPubKey.
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput}, []*wire.TxOut{
		{Value: maxAllowedOutput, PkScript: carolPkScript},
		{Value: policyOutput.Value - maxAllowedOutput, PkScript: alicePkScript},
	})

	// Valid: <= 1000 to recipient, change back to same policy scriptPubKey.
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: maxAllowedOutput, PkScript: carolPkScript},
			{Value: policyOutput.Value - maxAllowedOutput, PkScript: inputPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)
	require.Equal(t, inputPkScript, validTx.Inputs[0].WitnessUtxo.PkScript)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{{Vin: 0, Script: arkadeScript}})
	require.NoError(t, executeArkadeScripts(t, validTx, introspectorPubKey))
	submitAndFinalize(validTx, validCheckpoints)

	// Spend the recursive output again to prove it remains spendable.
	nextVtxoInput := vtxoInputFromOutput(validTx.UnsignedTx, 1)

	nextTx, nextCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{nextVtxoInput},
		[]*wire.TxOut{
			{Value: maxAllowedOutput, PkScript: carolPkScript},
			{Value: validTx.UnsignedTx.TxOut[1].Value - maxAllowedOutput, PkScript: inputPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)
	require.Equal(t, inputPkScript, nextTx.Inputs[0].WitnessUtxo.PkScript)

	addIntrospectorPacket(t, nextTx, []arkade.IntrospectorEntry{{Vin: 0, Script: arkadeScript}})
	require.NoError(t, executeArkadeScripts(t, nextTx, introspectorPubKey))
	submitAndFinalize(nextTx, nextCheckpoints)
}
