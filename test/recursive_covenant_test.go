package test

import (
	"encoding/hex"
	"strings"
	"testing"

	"context"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
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

	policyPkScript, err := txscript.PayToTaprootScript(policyTapKey)
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
			Index: 0,
		},
		Tapscript:          tapscript,
		Amount:             policyAmount,
		RevealedTapscripts: []string{hex.EncodeToString(policyTapscript)},
	}
	vtxoInput2 := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: 1,
		},
		Tapscript:          tapscript,
		Amount:             policyAmount,
		RevealedTapscripts: []string{hex.EncodeToString(policyTapscript)},
	}

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

		signedCheckpoints := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)

			signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
			require.NoError(t, err)
			signedCheckpoints = append(signedCheckpoints, signed)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		require.NoError(t, err)
		indexerOpts := setupIndexer(t)
		opts := indexer.GetVtxosRequestOption{}
		err = opts.WithOutpoints([]types.Outpoint{
			{Txid: candidateTx.UnsignedTx.TxID(), VOut: 0},
			{Txid: candidateTx.UnsignedTx.TxID(), VOut: 1},
		})
		require.NoError(t, err)
		vtxos, err := indexerOpts.GetVtxos(ctx, opts)
		require.NoError(t, err)
		require.Len(t, vtxos.Vtxos, 2)
		for _, vtxo := range vtxos.Vtxos {
			require.True(t, vtxo.Preconfirmed)
			require.False(t, vtxo.Spent)
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

		signedCheckpoints := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)

			signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
			require.NoError(t, err)
			signedCheckpoints = append(signedCheckpoints, signed)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	// Invalid: policy script requires exactly one input.
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput, vtxoInput2}, []*wire.TxOut{
		{Value: maxAllowedOutput, PkScript: carolPkScript},
		{Value: policyAmount - maxAllowedOutput, PkScript: policyPkScript},
		{Value: policyAmount, PkScript: policyPkScript},
	})

	// Invalid: recipient amount is not <= 1000.
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput}, []*wire.TxOut{
		{Value: maxAllowedOutput + 1, PkScript: carolPkScript},
		{Value: policyAmount - int64(maxAllowedOutput+1), PkScript: policyPkScript},
	})

	// Invalid: recursive output does not receive the full remainder
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput}, []*wire.TxOut{
		{Value: maxAllowedOutput, PkScript: carolPkScript},
		{Value: policyAmount - maxAllowedOutput - 1, PkScript: policyPkScript},
		{Value: 1, PkScript: carolPkScript},
	})

	// Invalid: output 1 does not return to the policy scriptPubKey.
	submitAndExpectFailure([]offchain.VtxoInput{vtxoInput}, []*wire.TxOut{
		{Value: maxAllowedOutput, PkScript: carolPkScript},
		{Value: policyAmount - maxAllowedOutput, PkScript: alicePkScript},
	})

	// Valid: <= 1000 to recipient, change back to same policy scriptPubKey.
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: maxAllowedOutput, PkScript: carolPkScript},
			{Value: policyAmount - maxAllowedOutput, PkScript: policyPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{{Vin: 0, Script: arkadeScript}})
	require.NoError(t, executeArkadeScripts(t, validTx, introspectorPubKey))
	require.NoError(t, txutils.SetArkPsbtField(validTx, 0, arkade.PrevoutTxField, *fundingPtx.UnsignedTx))
	submitAndFinalize(validTx, validCheckpoints)

	// Spend the recursive output again to prove it remains spendable.
	nextTx, nextCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{{
			Outpoint: &wire.OutPoint{
				Hash:  validTx.UnsignedTx.TxHash(),
				Index: 1,
			},
			Tapscript:          tapscript,
			Amount:             policyAmount - maxAllowedOutput,
			RevealedTapscripts: []string{hex.EncodeToString(policyTapscript)},
		}},
		[]*wire.TxOut{
			{Value: maxAllowedOutput, PkScript: carolPkScript},
			{Value: policyAmount - (maxAllowedOutput * 2), PkScript: policyPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, nextTx, []arkade.IntrospectorEntry{{Vin: 0, Script: arkadeScript}})
	require.NoError(t, executeArkadeScripts(t, nextTx, introspectorPubKey))
	require.NoError(t, txutils.SetArkPsbtField(nextTx, 0, arkade.PrevoutTxField, *validTx.UnsignedTx))
	submitAndFinalize(nextTx, nextCheckpoints)
}
