package arkade

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestPrevArkTxField(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		err := txutils.SetArkPsbtField(ptx, 0, PrevArkTxField, *prevTx)
		require.NoError(t, err)

		fields, err := txutils.GetArkPsbtFields(ptx, 0, PrevArkTxField)
		require.NoError(t, err)
		require.Len(t, fields, 1)
		require.Equal(t, prevTx.TxHash(), fields[0].TxHash())
	})
}

func TestPrevoutTxField(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(2)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		err := txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx)
		require.NoError(t, err)

		fields, err := txutils.GetArkPsbtFields(ptx, 0, PrevoutTxField)
		require.NoError(t, err)
		require.Len(t, fields, 1)
		require.Equal(t, prevTx.TxHash(), fields[0].TxHash())
	})

	t.Run("does not collide with PrevArkTxField", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		arkTx := newTestPrevoutTx(1)
		outTx := newTestPrevoutTx(2)

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevArkTxField, *arkTx))
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *outTx))

		arkFields, err := txutils.GetArkPsbtFields(ptx, 0, PrevArkTxField)
		require.NoError(t, err)
		require.Len(t, arkFields, 1)
		require.Equal(t, arkTx.TxHash(), arkFields[0].TxHash())

		outFields, err := txutils.GetArkPsbtFields(ptx, 0, PrevoutTxField)
		require.NoError(t, err)
		require.Len(t, outFields, 1)
		require.Equal(t, outTx.TxHash(), outFields[0].TxHash())
	})
}

func newTestPSBT(t *testing.T, numInputs int) *psbt.Packet {
	t.Helper()

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	require.NoError(t, err)

	ptx.UnsignedTx.TxIn = make([]*wire.TxIn, 0, numInputs)
	ptx.Inputs = make([]psbt.PInput, 0, numInputs)

	for i := 0; i < numInputs; i++ {
		ptx.UnsignedTx.TxIn = append(ptx.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: uint32(i),
			},
		})
		ptx.Inputs = append(ptx.Inputs, psbt.PInput{})
	}

	return ptx
}

func newTestPrevoutTx(tag byte) *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{tag},
			Index: 0,
		},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    int64(tag) + 1,
		PkScript: []byte{txscript.OP_TRUE},
	})
	return tx
}
