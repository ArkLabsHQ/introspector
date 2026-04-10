package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitTx aims to execute arkade scripts on offchain ark transactions
// execution of the script runs only on ark tx, if valid, the associated checkpoint tx
func (s *service) SubmitTx(ctx context.Context, tx OffchainTx) (*OffchainTx, error) {
	arkPtx := tx.ArkTx

	// index checkpoints by txid for easy lookup while signing ark transaction
	indexedCheckpoints := make(map[string]*psbt.Packet) // txid => checkpoint psbt
	for _, checkpoint := range tx.Checkpoints {
		indexedCheckpoints[checkpoint.UnsignedTx.TxID()] = checkpoint
	}
	// preserve original checkpoint order for deterministic response
	orderedCheckpointTxids := make([]string, 0, len(tx.Checkpoints))
	for _, checkpoint := range tx.Checkpoints {
		orderedCheckpointTxids = append(orderedCheckpointTxids, checkpoint.UnsignedTx.TxID())
	}

	prevoutFetcher, err := computePrevoutFetcher(arkPtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	arkPrevOutFetcher, err := arkPrevOutFetcherForArkTxFromPSBT(arkPtx, tx.Checkpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to decode prev ark txs: %w", err)
	}

	// Parse IntrospectorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindIntrospectorPacket(arkPtx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse introspector packet: %w", err)
	}

	if len(packet) == 0 {
		return nil, fmt.Errorf("no introspector packet found in transaction")
	}

	signerPublicKey := s.signer.secretKey.PubKey()

	var nSigned = 0
	for _, entry := range packet {
		inputIndex := int(entry.Vin)
		script, err := arkade.ReadArkadeScript(arkPtx, signerPublicKey, entry)
		if err != nil {
			// there may be input/entry pairs attributed to a different signer
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(arkPtx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(
			arkPtx.UnsignedTx,
			prevoutFetcher,
			arkPrevOutFetcher,
			inputIndex,
		); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		if err := s.signer.signInput(arkPtx, inputIndex, script.Hash(), prevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// search for checkpoint
		inputTxid := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash.String()
		checkpointPtx, ok := indexedCheckpoints[inputTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}

		checkpointPrevoutFetcher, err := computePrevoutFetcher(checkpointPtx)
		if err != nil {
			return nil, fmt.Errorf("failed to create prevout fetcher for checkpoint: %w", err)
		}

		if err := s.signer.signInput(checkpointPtx, 0, script.Hash(), checkpointPrevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign checkpoint input %d: %w", inputIndex, err)
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	signedCheckpointTxs := make([]*psbt.Packet, 0, len(orderedCheckpointTxids))
	for _, txid := range orderedCheckpointTxids {
		signedCheckpointTxs = append(signedCheckpointTxs, indexedCheckpoints[txid])
	}

	return &OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: signedCheckpointTxs,
	}, nil
}
