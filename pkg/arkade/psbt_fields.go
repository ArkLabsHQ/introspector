package arkade

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

var (
	ArkFieldPrevoutTx                                = []byte("prevarktx")
	PrevoutTxField    ArkPsbtFieldCoder[*wire.MsgTx] = arkPsbtFieldCoderPrevoutTx{}
)

// ArkPsbtFieldCoder mirrors arkd's psbt field pattern, but uses an explicit
// found flag instead of nil-for-not-found. That avoids awkward double pointers
// for pointer payloads such as *wire.MsgTx.
type ArkPsbtFieldCoder[T any] interface {
	Encode(T) (*psbt.Unknown, error)
	Decode(*psbt.Unknown) (T, bool, error)
}

func SetArkPsbtField[T any](ptx *psbt.Packet, inputIndex int, coder ArkPsbtFieldCoder[T], value T) error {
	if len(ptx.Inputs) <= inputIndex {
		return fmt.Errorf("input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs))
	}

	arkField, err := coder.Encode(value)
	if err != nil {
		return err
	}

	ptx.Inputs[inputIndex].Unknowns = append(ptx.Inputs[inputIndex].Unknowns, arkField)
	return nil
}

func GetArkPsbtFields[T any](ptx *psbt.Packet, inputIndex int, coder ArkPsbtFieldCoder[T]) ([]T, error) {
	if len(ptx.Inputs) <= inputIndex {
		return nil, fmt.Errorf("input index out of bounds %d, len(inputs)=%d", inputIndex, len(ptx.Inputs))
	}

	fieldsFound := make([]T, 0)

	for _, unknown := range ptx.Inputs[inputIndex].Unknowns {
		value, ok, err := coder.Decode(unknown)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		fieldsFound = append(fieldsFound, value)
	}

	return fieldsFound, nil
}

func PrevoutTxsFromPSBT(ptx *psbt.Packet) (map[int]*wire.MsgTx, error) {
	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}

	prevoutTxs := make(map[int]*wire.MsgTx)

	for inputIndex := range ptx.Inputs {
		fields, err := GetArkPsbtFields(ptx, inputIndex, PrevoutTxField)
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
		if prevTx == nil {
			return nil, fmt.Errorf("prevout tx is nil for input %d", inputIndex)
		}

		expectedHash := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash
		actualHash := prevTx.TxHash()
		if actualHash != expectedHash {
			return nil, fmt.Errorf(
				"prevout tx hash mismatch for input %d: got %s, expected %s",
				inputIndex, actualHash, expectedHash,
			)
		}

		prevoutTxs[inputIndex] = prevTx
	}

	return prevoutTxs, nil
}

type arkPsbtFieldCoderPrevoutTx struct{}

func (c arkPsbtFieldCoderPrevoutTx) Encode(tx *wire.MsgTx) (*psbt.Unknown, error) {
	if tx == nil {
		return nil, fmt.Errorf("prevout tx is nil")
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}

	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkFieldPrevoutTx),
		Value: buf.Bytes(),
	}, nil
}

func (c arkPsbtFieldCoderPrevoutTx) Decode(unknown *psbt.Unknown) (*wire.MsgTx, bool, error) {
	if !containsArkPsbtKey(unknown, ArkFieldPrevoutTx) {
		return nil, false, nil
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(unknown.Value)); err != nil {
		return nil, false, err
	}

	return tx, true, nil
}

func makeArkPsbtKey(keyData []byte) []byte {
	return append([]byte{txutils.ArkPsbtFieldKeyType}, keyData...)
}

// Keep key matching strict here even though arkd's transitional decoder is
// currently looser. This field is newly introduced, so requiring the canonical
// [0xde]["prevarktx"] key prevents accidental matches against unrelated
// unknowns and makes malformed producer behavior fail closed.
func containsArkPsbtKey(unknownField *psbt.Unknown, keyFieldName []byte) bool {
	if len(unknownField.Key) == 0 {
		return false
	}

	return bytes.Equal(unknownField.Key, makeArkPsbtKey(keyFieldName))
}
