package application

import (
	"context"
	"fmt"

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

	signerPublicKey := s.signer.secretKey.PubKey()

	for inputIndex := range arkPtx.Inputs {
		script, err := readArkadeScript(arkPtx, inputIndex, signerPublicKey)
		if err != nil {
			// skip if the input is not an arkade script
			continue
		}

		log.Debugf("executing arkade script: %x", script.script)
		if err := script.execute(arkPtx.UnsignedTx, prevoutFetcher, inputIndex); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w", err)
		}
		log.Debugf("execution of %x succeeded", script.script)

		if err := s.signer.signInput(arkPtx, inputIndex, script.hash, prevoutFetcher); err != nil {
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

		if err := s.signer.signInput(checkpointPtx, 0, script.hash, checkpointPrevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign checkpoint input %d: %w", inputIndex, err)
		}
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
