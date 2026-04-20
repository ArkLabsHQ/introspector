package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/explorer"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestCounterContractBatchContinuation pins down the current inability to carry
// custom contract packets through a batch-swap intent.
//
// Semantics: the first batch swap is a real contract transition. The intent
// proof spends the current counter VTXO, carries counter=1 in its output
// packets, and outputs the same value back to the same contract script. The
// introspector executes the arkade script against that intent proof and signs
// only because counter=1 is a valid transition from the deployed counter=0.
//
// The missing piece today is packet propagation from the intent proof into the
// new batch leaf tx. arkd currently drops every extension packet except the
// asset packet (type 0x00) when building the leaf tx, so the counter=1 packet
// is lost. Tracked in https://github.com/arkade-os/arkd/issues/1017.
//
// The test asserts that consequence: after the first increment lands in the
// next batch, a second increment intent fails because OP_INSPECTINPUTPACKET
// cannot recover the previous counter packet from the batch leaf tx.
//
// TODO: flip the second increment to a success assertion once arkd carries
// custom extension packets from swap intents into the created batch leaf tx.
func TestCounterContractBatchContinuation(t *testing.T) {
	ctx := t.Context()

	alice, aliceWallet, alicePubKey, grpcClient := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 50000)

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

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	// =========================================================================
	// Phase 1: Deploy the counter at counter=0 from Alice's wallet VTXO.
	// =========================================================================

	counterArkadeScript := counterContractArkadeScript(t)
	counterVtxoScript := createVtxoScriptWithArkadeAndCSV(
		alicePubKey,
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(counterArkadeScript),
	)
	counterTapscript := onlyForfeitScript(t, counterVtxoScript)
	counterPkScript := p2trScriptForVtxoScript(t, counterVtxoScript)
	counterRevealedTapscripts, err := counterVtxoScript.Encode()
	require.NoError(t, err)

	deployTx := deployCounterFromWallet(
		t,
		ctx,
		alice,
		aliceWallet,
		grpcClient,
		indexerSvc,
		alicePubKey,
		aliceAddr.Signer,
		uint32(infos.UnilateralExitDelay),
		counterPkScript,
		checkpointScriptBytes,
	)

	// =========================================================================
	// Phase 2: Increment from counter=0 to counter=1 through a swap intent.
	//
	// The intent proof spends the counter VTXO, carries counter=1, and asks
	// arkd to create the same contract output in the next batch.
	// =========================================================================

	counterVtxoAmount := deployTx.UnsignedTx.TxOut[0].Value

	cosignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerSession := tree.NewTreeSignerSession(cosignerKey)

	firstIntentPtx, firstMessage := buildCounterIncrementIntent(
		t,
		signerSession,
		deployTx.UnsignedTx,
		0,
		counterVtxoScript,
		counterTapscript,
		counterPkScript,
		counterArkadeScript,
		1,
	)
	requireCounterPacket(t, firstIntentPtx.UnsignedTx, 1)
	require.NoError(t, executeArkadeScripts(t, firstIntentPtx, nil, introspectorPubKey))

	signedIntent := signAndSubmitCounterIntent(
		t,
		ctx,
		aliceWallet,
		explorer,
		introspectorClient,
		firstIntentPtx,
		firstMessage,
	)

	intentId, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: deployTx.UnsignedTx.TxHash().String(),
				VOut: 0,
			},
			Script: hex.EncodeToString(counterTapscript),
			Amount: uint64(counterVtxoAmount),
		},
		Tapscripts: counterRevealedTapscripts,
	}

	batchHandler := &capturingBatchEventsHandler{
		delegateBatchEventsHandler: &delegateBatchEventsHandler{
			intentId:           intentId,
			intent:             signedIntent,
			vtxosToForfeit:     []client.TapscriptsVtxo{vtxo},
			signerSession:      signerSession,
			introspectorClient: introspectorClient,
			wallet:             aliceWallet,
			client:             grpcClient,
			explorer:           explorer,
		},
	}

	topics := arksdk.GetEventStreamTopics(
		[]types.Outpoint{vtxo.Outpoint},
		[]tree.SignerSession{signerSession},
	)
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
	})

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, batchHandler)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
	require.NotNil(t, batchHandler.vtxoTree)

	// =========================================================================
	// Phase 3: Try another increment from the newly created batch leaf VTXO.
	//
	// This currently fails because the leaf tx does not retain the counter=1
	// extension packet from the first swap intent.
	// =========================================================================

	nextCounterTx, nextCounterVout := findCounterLeafOutput(
		t, batchHandler.vtxoTree, counterPkScript, counterVtxoAmount,
	)
	requireNoCounterPacket(t, nextCounterTx)

	secondSignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	secondSignerSession := tree.NewTreeSignerSession(secondSignerKey)

	secondIntentPtx, secondMessage := buildCounterIncrementIntent(
		t,
		secondSignerSession,
		nextCounterTx,
		nextCounterVout,
		counterVtxoScript,
		counterTapscript,
		counterPkScript,
		counterArkadeScript,
		2,
	)
	requireCounterPacket(t, secondIntentPtx.UnsignedTx, 2)

	err = executeArkadeScripts(t, secondIntentPtx, nil, introspectorPubKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "OP_EQUALVERIFY")

	encodedSecondIntentProof, err := secondIntentPtx.B64Encode()
	require.NoError(t, err)
	signedSecondIntentProof, err := aliceWallet.SignTransaction(
		ctx, explorer, encodedSecondIntentProof,
	)
	require.NoError(t, err)

	_, err = introspectorClient.SubmitIntent(ctx, introspectorclient.Intent{
		Proof:   signedSecondIntentProof,
		Message: secondMessage,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process intent")
}

type capturingBatchEventsHandler struct {
	*delegateBatchEventsHandler
	vtxoTree *tree.TxTree
}

func (h *capturingBatchEventsHandler) OnBatchFinalization(
	ctx context.Context,
	event client.BatchFinalizationEvent,
	vtxoTree, connectorTree *tree.TxTree,
) error {
	h.vtxoTree = vtxoTree
	return h.delegateBatchEventsHandler.OnBatchFinalization(ctx, event, vtxoTree, connectorTree)
}

func buildCounterIncrementIntent(
	t *testing.T,
	signerSession tree.SignerSession,
	prevArkTx *wire.MsgTx,
	prevVout uint32,
	counterVtxoScript script.TapscriptsVtxoScript,
	counterTapscript []byte,
	counterPkScript []byte,
	counterArkadeScript []byte,
	nextCounterValue uint64,
) (*psbt.Packet, string) {
	t.Helper()

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

	require.True(t, prevVout < uint32(len(prevArkTx.TxOut)))
	counterVtxoAmount := prevArkTx.TxOut[prevVout].Value
	require.Equal(t, counterPkScript, prevArkTx.TxOut[prevVout].PkScript)

	intentProof, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  prevArkTx.TxHash(),
					Index: prevVout,
				},
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: prevArkTx.TxOut[prevVout],
			},
		},
		[]*wire.TxOut{
			{
				Value:    counterVtxoAmount,
				PkScript: counterPkScript,
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
	addCounterPacket(t, intentPtx, nextCounterValue)
	addIntrospectorPacket(t, intentPtx, []arkade.IntrospectorEntry{
		{Vin: 1, Script: counterArkadeScript},
	})
	require.NoError(t, txutils.SetArkPsbtField(
		intentPtx, 1, arkade.PrevArkTxField, *prevArkTx,
	))

	return intentPtx, message
}

func signAndSubmitCounterIntent(
	t *testing.T,
	ctx context.Context,
	walletSvc wallet.WalletService,
	explorerSvc explorer.Explorer,
	introspectorClient introspectorclient.TransportClient,
	intentPtx *psbt.Packet,
	message string,
) introspectorclient.Intent {
	t.Helper()

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	signedIntentProof, err := walletSvc.SignTransaction(ctx, explorerSvc, encodedIntentProof)
	require.NoError(t, err)

	approvedIntentProof, err := introspectorClient.SubmitIntent(ctx, introspectorclient.Intent{
		Proof:   signedIntentProof,
		Message: message,
	})
	require.NoError(t, err)

	return introspectorclient.Intent{
		Proof:   approvedIntentProof,
		Message: message,
	}
}

func findCounterLeafOutput(
	t *testing.T,
	vtxoTree *tree.TxTree,
	counterPkScript []byte,
	counterVtxoAmount int64,
) (*wire.MsgTx, uint32) {
	t.Helper()

	for _, leaf := range vtxoTree.Leaves() {
		for vout, output := range leaf.UnsignedTx.TxOut {
			if output.Value == counterVtxoAmount && bytes.Equal(output.PkScript, counterPkScript) {
				return leaf.UnsignedTx, uint32(vout)
			}
		}
	}

	require.FailNow(t, "counter leaf output not found")
	return nil, 0
}

func requireNoCounterPacket(t *testing.T, tx *wire.MsgTx) {
	t.Helper()

	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		require.ErrorIs(t, err, extension.ErrExtensionNotFound)
		return
	}

	for _, packet := range ext {
		require.NotEqual(t, uint8(counterPacketType), packet.Type())
	}
}
