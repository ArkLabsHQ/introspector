package application

import (
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// PrevoutTxsFromPSBT extracts per-input prevout transactions from Ark PSBT
// unknown fields and validates that each provided transaction matches the
// prevout hash referenced by the corresponding input.
func PrevoutTxsFromPSBT(ptx *psbt.Packet) (map[int]*wire.MsgTx, error) {
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
		expectedHash := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash
		actualHash := prevTx.TxHash()
		if actualHash != expectedHash {
			return nil, fmt.Errorf(
				"prevout tx hash mismatch for input %d: got %s, expected %s",
				inputIndex, actualHash, expectedHash,
			)
		}

		prevTxCopy := prevTx
		prevoutTxs[inputIndex] = &prevTxCopy
	}

	return prevoutTxs, nil
}
