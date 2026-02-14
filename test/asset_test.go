package test

import (
	"bytes"
	"context"
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
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
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

// TestOffchainTxWithAsset tests an offchain transaction with asset introspection opcodes.
// The test creates a simple asset packet with one asset group (issuance) and verifies
// that the arkade script can correctly inspect the asset using the introspection opcodes.
func TestOffchainTxWithAsset(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	bobWallet, _, bobPubKey := setupBobWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice)

	const sendAmount = 10000
	const assetAmount = 1000

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	assetPacket := createAssetPacket(t, 0, assetAmount)
	arkadeScript := createArkadeScriptWithAssetChecks(t, alicePkScript, assetAmount)
	introspectorClient, publicKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	vtxoScript := createVtxoScriptWithArkade(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(arkadeScript))

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := arklib.Address{
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

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	// Build transaction with asset packet
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Tapscript:          tapscript,
				Amount:             bobOutput.Value,
				RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscript)},
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value,
				PkScript: alicePkScript,
			},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Add the arkade script field
	err = txutils.SetArkPsbtField(validTx, 0, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	// Add the asset packet to the transaction as an OP_RETURN output
	assetPacketOut, err := assetPacket.TxOut()
	require.NoError(t, err)
	validTx.UnsignedTx.AddTxOut(assetPacketOut)
	validTx.Outputs = append(validTx.Outputs, psbt.POutput{})

	encodedValidTx, err := validTx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(
		ctx,
		explorer,
		encodedValidTx,
	)
	require.NoError(t, err)

	encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, checkpoint := range validCheckpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)
		encodedValidCheckpoints = append(encodedValidCheckpoints, encoded)
	}

	// Submit to introspector - should succeed as the asset introspection opcodes will validate correctly
	signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)
	require.NotEmpty(t, signedTx)
	require.NotEmpty(t, signedByIntrospectorCheckpoints)

	// Also submit to server
	txid, _, signedByServerCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedByIntrospectorCheckpoints))
	for i, checkpoint := range signedByServerCheckpoints {
		finalCheckpoint, err := bobWallet.SignTransaction(
			ctx,
			explorer,
			checkpoint,
		)
		require.NoError(t, err)

		// Combine server and introspector checkpoints
		byInterceptorCheckpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedByIntrospectorCheckpoints[i]), true)
		require.NoError(t, err)

		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalCheckpoint), true)
		require.NoError(t, err)

		checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
			checkpointPtx.Inputs[0].TaprootScriptSpendSig,
			byInterceptorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
		)

		finalCheckpoint, err = checkpointPtx.B64Encode()
		require.NoError(t, err)

		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, txid, finalCheckpoints)
	require.NoError(t, err)
}

// TestSettlementWithAsset tests the settlement flow with an asset packet in the intent.
// Similar to TestSettlement but includes asset introspection in the arkade script.
func TestSettlementWithAsset(t *testing.T) {
	ctx := context.Background()
	alice, grpcClient := setupArkSDK(t)
	defer grpcClient.Close()

	bobWallet, _, bobPubKey := setupBobWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice)

	const sendAmount = 10000
	const assetAmount = 500

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	arkadeScript := createArkadeScriptWithAssetChecks(t, alicePkScript, assetAmount)
	introspectorClient, publicKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	vtxoScript := createVtxoScriptWithArkadeAndCSV(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(arkadeScript))

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	contractAddress := arklib.Address{
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

	contractAddressStr, err := contractAddress.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: contractAddressStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var contractOutput *wire.TxOut
	var contractOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(contractAddress.VtxoTapKey)) {
			contractOutput = out
			contractOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, contractOutput)

	// Create the intent with asset packet

	randomKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	treeSignerSession := tree.NewTreeSignerSession(randomKey)
	require.NoError(t, err)

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: nil,
		ExpireAt:             0,
		ValidAt:              0,
		CosignersPublicKeys:  []string{treeSignerSession.GetPublicKey()},
	}.Encode()
	require.NoError(t, err)

	intentProof, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: contractOutputIndex,
				},
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: contractOutput,
			},
		},
		[]*wire.TxOut{
			{
				Value:    contractOutput.Value,
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, intentProof)

	// Add asset packet to intent transaction
	assetPacket := createAssetPacket(t, 0, assetAmount)
	assetPacketOut, err := assetPacket.TxOut()
	require.NoError(t, err)

	// Add asset packet as OP_RETURN output to intent transaction
	intentProof.UnsignedTx.AddTxOut(assetPacketOut)
	intentProof.Outputs = append(intentProof.Outputs, psbt.POutput{})

	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(tapscripts)
	require.NoError(t, err)

	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	tapLeafScript := []*psbt.TaprootTapLeafScript{
		{
			LeafVersion:  txscript.BaseLeafVersion,
			ControlBlock: ctrlBlockBytes,
			Script:       merkleProof.Script,
		},
	}
	intentProof.Inputs[0].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[1].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[0].Unknowns = append(intentProof.Inputs[0].Unknowns, taptreeField)
	intentProof.Inputs[1].Unknowns = append(intentProof.Inputs[1].Unknowns, taptreeField)

	intentPtx := &intentProof.Packet
	err = txutils.SetArkPsbtField(intentPtx, 1, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedIntentProof, err := bobWallet.SignTransaction(ctx, explorer, encodedIntentProof)
	require.NoError(t, err)
	require.NotEqual(t, signedIntentProof, encodedIntentProof)

	// SubmitIntent will execute the arkade script on the intent tx with the asset packet
	approvedIntentProof, err := introspectorClient.SubmitIntent(ctx, introspectorclient.Intent{
		Proof:   signedIntentProof,
		Message: message,
	})
	require.NoError(t, err)

	signedIntent := introspectorclient.Intent{
		Proof:   approvedIntentProof,
		Message: message,
	}

	intentId, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: redeemPtx.UnsignedTx.TxHash().String(),
				VOut: contractOutputIndex,
			},
			Script: hex.EncodeToString(arkadeTapscript),
			Amount: uint64(contractOutput.Value),
		},
		Tapscripts: tapscripts,
	}

	introspectorBatchHandler := &delegateBatchEventsHandler{
		intentId:           intentId,
		intent:             signedIntent,
		vtxosToForfeit:     []client.TapscriptsVtxo{vtxo},
		signerSession:      treeSignerSession,
		introspectorClient: introspectorClient,
		wallet:             bobWallet,
		client:             grpcClient,
	}

	topics := arksdk.GetEventStreamTopics([]types.Outpoint{vtxo.Outpoint}, []tree.SignerSession{treeSignerSession})
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
	})

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, introspectorBatchHandler)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}
