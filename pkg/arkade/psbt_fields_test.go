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

func TestPrevoutTxField(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		err := txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx)
		require.NoError(t, err)

		fields, err := txutils.GetArkPsbtFields(ptx, 0, PrevoutTxField)
		require.NoError(t, err)
		require.Len(t, fields, 1)
		require.Equal(t, prevTx.TxHash(), fields[0].TxHash())
	})

	t.Run("extract prev ark txs from psbt", func(t *testing.T) {
		ptx := newTestPSBT(t, 2)
		prevTx0 := newTestPrevoutTx(1)
		prevTx1 := newTestPrevoutTx(2)

		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx0.TxHash()
		ptx.UnsignedTx.TxIn[1].PreviousOutPoint.Hash = prevTx1.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx0))
		require.NoError(t, txutils.SetArkPsbtField(ptx, 1, PrevoutTxField, *prevTx1))

		prevoutTxs, err := PrevoutTxsFromPSBT(ptx)
		require.NoError(t, err)
		require.Len(t, prevoutTxs, 2)
		require.Equal(t, prevTx0.TxHash(), prevoutTxs[0].TxHash())
		require.Equal(t, prevTx1.TxHash(), prevoutTxs[1].TxHash())
	})

	t.Run("reject mismatched prevout hash", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = chainhash.Hash{9, 9, 9}

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx))

		_, err := PrevoutTxsFromPSBT(ptx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "prevout tx hash mismatch")
	})

	t.Run("reject duplicate prevout tx fields", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx))
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx))

		_, err := PrevoutTxsFromPSBT(ptx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple prevout tx fields")
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
