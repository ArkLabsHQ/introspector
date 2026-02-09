package application

import (
	"bytes"
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SubmitFinalization doesn't execute arkade scripts, it only signs the forfeits and the commitment tx
// if and only if the intent proof contains the signer's signature (it means we executed the arkade script in the past)
// before signing the forfeits, we also verify that is it part of the commitment tx
func (s *service) SubmitFinalization(ctx context.Context, finalization BatchFinalization) (*SignedBatchFinalization, error) {
	signerPublicKey := s.signer.secretKey.PubKey()
	signedInputs, err := getSignedInputs(finalization.Intent.Proof.Packet, signerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed inputs: %w", err)
	}

	if len(signedInputs) == 0 {
		return nil, fmt.Errorf("no signed inputs found")
	}

	signedForfeits := make([]*psbt.Packet, 0)

	for _, forfeit := range finalization.Forfeits {
		if len(forfeit.Inputs) != 2 {
			return nil, fmt.Errorf(
				"malformed forfeit %s: expected 2 inputs, got %d",
				forfeit.UnsignedTx.TxID(), len(forfeit.Inputs),
			)
		}
		if len(forfeit.UnsignedTx.TxIn) != 2 {
			return nil, fmt.Errorf(
				"malformed forfeit %s: expected 2 inputs, got %d",
				forfeit.UnsignedTx.TxID(), len(forfeit.UnsignedTx.TxIn),
			)
		}

		for inputIndex, input := range forfeit.UnsignedTx.TxIn {
			arkadeScript, ok := signedInputs[input.PreviousOutPoint]
			if !ok {
				continue
			}

			// validate connector is part of the connector tree
			connectorIndex := inputIndex ^ 1 // if inputIndex is 0, connectorIndex is 1, and vice versa
			connector := forfeit.UnsignedTx.TxIn[connectorIndex].PreviousOutPoint
			if !hasLeaf(finalization.ConnectorTree, connector) {
				return nil, fmt.Errorf("connector %s is not part of the tree", connector)
			}

			// sign the forfeit
			prevoutFetcher, err := computePrevoutFetcher(forfeit)
			if err != nil {
				return nil, err
			}
			if err := s.signer.signInput(forfeit, inputIndex, arkadeScript.hash, prevoutFetcher); err != nil {
				return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
			}
			signedForfeits = append(signedForfeits, forfeit)
			delete(signedInputs, input.PreviousOutPoint)
		}
	}

	signedBatchFinalization := &SignedBatchFinalization{
		Forfeits: signedForfeits,
	}

	if len(signedForfeits) == len(signedInputs) {
		// all forfeits are signed, it means no boarding inputs, we can return
		return signedBatchFinalization, nil
	}

	prevoutFetcher, err := computePrevoutFetcher(finalization.CommitmentTx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher for commitment tx: %w", err)
	}

	signed := false

	for inputIndex, input := range finalization.CommitmentTx.UnsignedTx.TxIn {
		arkadeScript, ok := signedInputs[input.PreviousOutPoint]
		if !ok {
			continue
		}

		if err := s.signer.signInput(
			finalization.CommitmentTx, inputIndex, arkadeScript.hash, prevoutFetcher,
		); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}
		signed = true
	}

	if signed {
		signedBatchFinalization.CommitmentTx = finalization.CommitmentTx
	}

	return signedBatchFinalization, nil
}

// getSignedInputs iterates over tapscript sigs to find arkade script inputs with valid signature
func getSignedInputs(ptx psbt.Packet, signerPublicKey *btcec.PublicKey) (map[wire.OutPoint]*arkadeScript, error) {
	prevoutFetcher, err := computePrevoutFetcher(&ptx)
	if err != nil {
		return nil, err
	}
	sighashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	signedInputs := make(map[wire.OutPoint]*arkadeScript)

	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}

	for inputIndex, input := range ptx.Inputs {
		if inputIndex == 0 {
			// in intent proof, input index 0 is the message input
			// it is not a valid vtxo output : no forfeit will be associated to it
			// we can skip it
			continue
		}

		if len(input.TaprootScriptSpendSig) == 0 {
			continue // not signed: skip
		}

		script, err := readArkadeScript(&ptx, inputIndex, signerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read arkade script: %w", err)
		}

		xOnlyPubKey := schnorr.SerializePubKey(script.pubkey)

		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, xOnlyPubKey) {
				continue
			}

			tapscriptSig, err := schnorr.ParseSignature(sig.Signature)
			if err != nil {
				return nil, fmt.Errorf("failed to parse tapscript signature: %w", err)
			}

			message, err := txscript.CalcTapscriptSignaturehash(
				sighashes, sig.SigHash, ptx.UnsignedTx, inputIndex, prevoutFetcher, script.tapLeaf,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate tapscript signature hash: %w", err)
			}

			if !tapscriptSig.Verify(message, script.pubkey) {
				return nil, fmt.Errorf("invalid signature for input %d", inputIndex)
			}

			signedInputs[ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint] = script
		}

	}
	return signedInputs, nil
}

func hasLeaf(tree *tree.TxTree, outpoint wire.OutPoint) bool {
	if tree == nil {
		fmt.Println("tree is nil")
		return false
	}

	flatTree, err := tree.Serialize()
	if err != nil {
		return false
	}
	leaves := flatTree.Leaves()
	for _, leaf := range leaves {
		fmt.Println("leaf", leaf.Txid)
	}

	node := tree.Find(outpoint.Hash.String())
	if node == nil {
		fmt.Println("node is nil")
		return false
	}

	if len(node.Children) != 0 {
		// not a leaf
		fmt.Println("not a leaf")
		return false
	}

	if len(node.Root.UnsignedTx.TxOut) <= int(outpoint.Index) {
		// index out of range
		fmt.Println("index out of range")
		return false
	}

	output := node.Root.UnsignedTx.TxOut[outpoint.Index]

	// false if the output is anchor
	return !bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT)
}
