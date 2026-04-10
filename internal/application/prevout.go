package application

import (
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func arkPrevOutFetcherForIntentFromPSBT(ptx *psbt.Packet) (arkade.ArkPrevOutFetcher, error) {
	prevoutTxs, err := decodePrevoutTxsFromPSBT(ptx)
	if err != nil {
		return nil, err
	}

	prevOutArkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	for inputIndex, prevTx := range prevoutTxs {
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
			return nil, err
		}
		prevOutArkTxs[outpoint] = prevTx
	}

	return arkade.NewMapArkPrevOutFetcher(prevOutArkTxs), nil
}

func arkPrevOutFetcherForArkTxFromPSBT(
	arkPtx *psbt.Packet, checkpoints []*psbt.Packet,
) (arkade.ArkPrevOutFetcher, error) {
	prevoutTxs, err := decodePrevoutTxsFromPSBT(arkPtx)
	if err != nil {
		return nil, err
	}

	checkpointsByTxid := make(map[string]*psbt.Packet, len(checkpoints))
	for _, checkpoint := range checkpoints {
		checkpointsByTxid[checkpoint.UnsignedTx.TxID()] = checkpoint
	}

	prevOutArkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	for inputIndex, prevTx := range prevoutTxs {
		outpoint := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		checkpointTxid := outpoint.Hash.String()
		checkpoint, ok := checkpointsByTxid[checkpointTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}
		if len(checkpoint.UnsignedTx.TxIn) == 0 {
			return nil, fmt.Errorf("checkpoint has no inputs for input %d", inputIndex)
		}

		checkpointInputPrevout := checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, checkpointInputPrevout.Hash); err != nil {
			return nil, err
		}

		if checkpointInputPrevout.Index >= uint32(len(prevTx.TxOut)) {
			return nil, fmt.Errorf(
				"prevout tx output index out of range for input %d: index=%d outputs=%d",
				inputIndex, checkpointInputPrevout.Index, len(prevTx.TxOut),
			)
		}

		prevOutArkTxs[outpoint] = prevTx
	}

	return arkade.NewMapArkPrevOutFetcher(prevOutArkTxs), nil
}

func decodePrevoutTxsFromPSBT(ptx *psbt.Packet) (map[int]*wire.MsgTx, error) {
	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}

	prevoutTxs := make(map[int]*wire.MsgTx)

	for inputIndex := range ptx.Inputs {
		fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevoutTxField)
		if err != nil {
			return nil, fmt.Errorf("failed to decode prevout tx for input %d: %w", inputIndex, err)
		}

		if len(fields) == 0 {
			continue
		}
		if len(fields) > 1 {
			return nil, fmt.Errorf("multiple prevout tx fields found for input %d", inputIndex)
		}

		prevTx := fields[0]
		prevTxCopy := prevTx
		prevoutTxs[inputIndex] = &prevTxCopy
	}

	return prevoutTxs, nil
}

func validatePrevoutTx(inputIndex int, prevTx *wire.MsgTx, expectedHash chainhash.Hash) error {
	actualHash := prevTx.TxHash()
	if actualHash != expectedHash {
		return fmt.Errorf(
			"prevout tx hash mismatch for input %d: got %s, expected %s",
			inputIndex, actualHash, expectedHash,
		)
	}

	return nil
}
