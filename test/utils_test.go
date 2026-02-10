package test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/explorer"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type delegateBatchEventsHandler struct {
	intentId           string
	intent             introspectorclient.Intent
	vtxosToForfeit     []client.TapscriptsVtxo
	signerSession      tree.SignerSession
	introspectorClient introspectorclient.TransportClient
	wallet             wallet.WalletService
	client             client.TransportClient
	explorer           explorer.Explorer

	forfeitAddress string

	batchExpiry  arklib.RelativeLocktime
	cacheBatchId string
}

func (h *delegateBatchEventsHandler) OnBatchStarted(
	ctx context.Context, event client.BatchStartedEvent,
) (bool, error) {
	buf := sha256.Sum256([]byte(h.intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := h.client.ConfirmRegistration(ctx, h.intentId); err != nil {
				return false, err
			}
			h.cacheBatchId = event.Id
			h.batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			return false, nil
		}
	}

	return true, nil
}

func (h *delegateBatchEventsHandler) OnBatchFinalized(
	_ context.Context, event client.BatchFinalizedEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnBatchFailed(
	_ context.Context, event client.BatchFailedEvent,
) error {
	if event.Id == h.cacheBatchId {
		return fmt.Errorf("batch failed: %s", event.Reason)
	}
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeTxEvent(context.Context, client.TreeTxEvent) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSignatureEvent(context.Context, client.TreeSignatureEvent) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	myPubkey := h.signerSession.GetPublicKey()
	if !slices.Contains(event.CosignersPubkeys, myPubkey) {
		return true, nil
	}

	arkInfos, err := h.client.GetInfo(ctx)
	if err != nil {
		return false, err
	}
	h.forfeitAddress = arkInfos.ForfeitAddress

	forfeitPubKeyBytes, err := hex.DecodeString(arkInfos.ForfeitPubKey)
	if err != nil {
		return false, err
	}
	forfeitPubKey, err := btcec.ParsePubKey(forfeitPubKeyBytes)
	if err != nil {
		return false, err
	}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPubKey}},
		Locktime:        h.batchExpiry,
	}

	script, err := sweepClosure.Script()
	if err != nil {
		return false, err
	}

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	generateAndSendNonces := func(session tree.SignerSession) error {
		if err := session.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}

		return h.client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces)
	}

	if err := generateAndSendNonces(h.signerSession); err != nil {
		return false, err
	}

	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNonces(context.Context, client.TreeNoncesEvent) (
	bool, error,
) {
	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNoncesAggregated(
	ctx context.Context, event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	h.signerSession.SetAggregatedNonces(event.Nonces)

	sigs, err := h.signerSession.Sign()
	if err != nil {
		return false, err
	}

	err = h.client.SubmitTreeSignatures(
		ctx,
		event.Id,
		h.signerSession.GetPublicKey(),
		sigs,
	)
	return err == nil, err
}

func (h *delegateBatchEventsHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent,
	vtxoTree, connectorTree *tree.TxTree,
) error {
	if len(h.vtxosToForfeit) <= 0 {
		return nil
	}

	if connectorTree == nil {
		return fmt.Errorf("connector tree is nil")
	}

	forfeits, err := h.createAndSignForfeits(ctx, h.vtxosToForfeit, connectorTree.Leaves())
	if err != nil {
		return err
	}

	flatConnectorTree, err := connectorTree.Serialize()
	if err != nil {
		return err
	}

	signedForfeits, signedCommitmentTx, err := h.introspectorClient.SubmitFinalization(
		ctx, h.intent, forfeits, flatConnectorTree, event.Tx,
	)
	if err != nil {
		return err
	}

	return h.client.SubmitSignedForfeitTxs(ctx, signedForfeits, signedCommitmentTx)
}

func (h *delegateBatchEventsHandler) OnStreamStartedEvent(client.StreamStartedEvent) {}

func (h *delegateBatchEventsHandler) createAndSignForfeits(
	ctx context.Context, vtxosToSign []client.TapscriptsVtxo, connectorsLeaves []*psbt.Packet,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(h.forfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	signedForfeitTxs := make([]string, 0, len(vtxosToSign))
	for i, vtxo := range vtxosToSign {
		connectorTx := connectorsLeaves[i]

		var connector *wire.TxOut
		var connectorOutpoint *wire.OutPoint
		for outIndex, output := range connectorTx.UnsignedTx.TxOut {
			if bytes.Equal(txutils.ANCHOR_PKSCRIPT, output.PkScript) {
				continue
			}

			connector = output
			connectorOutpoint = &wire.OutPoint{
				Hash:  connectorTx.UnsignedTx.TxHash(),
				Index: uint32(outIndex),
			}
			break
		}

		if connector == nil {
			return nil, fmt.Errorf("connector not found for vtxo %s", vtxo.Outpoint.String())
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		vtxoOutputScript, err := script.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoTxHash,
			Index: vtxo.VOut,
		}

		forfeitClosures := vtxoScript.ForfeitClosures()
		if len(forfeitClosures) <= 0 {
			return nil, fmt.Errorf("no forfeit closures found")
		}

		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, err
		}

		tapscript := psbt.TaprootTapLeafScript{
			ControlBlock: leafProof.ControlBlock,
			Script:       leafProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		vtxoLocktime := arklib.AbsoluteLocktime(0)
		if cltv, ok := forfeitClosure.(*script.CLTVMultisigClosure); ok {
			vtxoLocktime = cltv.Locktime
		}

		vtxoPrevout := &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoOutputScript,
		}

		vtxoSequence := wire.MaxTxInSequenceNum
		if vtxoLocktime != 0 {
			vtxoSequence = wire.MaxTxInSequenceNum - 1
		}

		forfeitTx, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{vtxoInput, connectorOutpoint},
			[]uint32{vtxoSequence, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{vtxoPrevout, connector},
			forfeitPkScript,
			uint32(vtxoLocktime),
		)
		if err != nil {
			return nil, err
		}

		forfeitTx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&tapscript}

		b64, err := forfeitTx.B64Encode()
		if err != nil {
			return nil, err
		}

		signedForfeitTx, err := h.wallet.SignTransaction(ctx, h.explorer, b64)
		if err != nil {
			return nil, err
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return signedForfeitTxs, nil
}

type boardingBatchEventsHandler struct {
	*delegateBatchEventsHandler
	boardingVtxo client.TapscriptsVtxo
}

func (h *boardingBatchEventsHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent,
	vtxoTree, connectorTree *tree.TxTree,
) error {
	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil {
		return err
	}

	boardingVtxoScript, err := script.ParseVtxoScript(h.boardingVtxo.Tapscripts)
	if err != nil {
		return err
	}

	forfeitClosures := boardingVtxoScript.ForfeitClosures()
	if len(forfeitClosures) <= 0 {
		return fmt.Errorf("no forfeit closures found")
	}

	forfeitClosure := forfeitClosures[0]

	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return err
	}

	_, taprootTree, err := boardingVtxoScript.TapTree()
	if err != nil {
		return err
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	forfeitProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return fmt.Errorf(
			"failed to get taproot merkle proof for boarding utxo: %s", err,
		)
	}

	tapscript := &psbt.TaprootTapLeafScript{
		ControlBlock: forfeitProof.ControlBlock,
		Script:       forfeitProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	for i := range commitmentPtx.Inputs {
		prevout := commitmentPtx.UnsignedTx.TxIn[i].PreviousOutPoint

		if h.boardingVtxo.Txid == prevout.Hash.String() &&
			h.boardingVtxo.VOut == prevout.Index {
			commitmentPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
				tapscript,
			}
			break
		}
	}

	b64, err := commitmentPtx.B64Encode()
	if err != nil {
		return err
	}

	signedCommitmentTx, err := h.wallet.SignTransaction(ctx, h.explorer, b64)
	if err != nil {
		return err
	}

	_, signedCommitmentTx, err = h.introspectorClient.SubmitFinalization(
		ctx, h.intent, []string{}, nil, signedCommitmentTx,
	)
	if err != nil {
		return err
	}

	return h.client.SubmitSignedForfeitTxs(ctx, []string{}, signedCommitmentTx)
}

func getBatchExpiryLocktime(expiry uint32) arklib.RelativeLocktime {
	if expiry >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: expiry}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: expiry}
}
