package application

import (
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestPrevoutTxsForIntentFromPSBT(t *testing.T) {
	t.Run("extract direct prevout txs from psbt", func(t *testing.T) {
		ptx := newTestPSBT(t, 2)
		prevTx0 := newTestPrevoutTx(1)
		prevTx1 := newTestPrevoutTx(2)

		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx0.TxHash()
		ptx.UnsignedTx.TxIn[1].PreviousOutPoint.Hash = prevTx1.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx0))
		require.NoError(t, txutils.SetArkPsbtField(ptx, 1, arkade.PrevoutTxField, *prevTx1))

		prevoutTxs, err := PrevoutTxsForIntentFromPSBT(ptx)
		require.NoError(t, err)
		require.Len(t, prevoutTxs, 2)
		require.Equal(t, prevTx0.TxHash(), prevoutTxs[0].TxHash())
		require.Equal(t, prevTx1.TxHash(), prevoutTxs[1].TxHash())
	})

	t.Run("reject mismatched prevout hash", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = chainhash.Hash{9, 9, 9}

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx))

		_, err := PrevoutTxsForIntentFromPSBT(ptx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "prevout tx hash mismatch")
	})

	t.Run("reject duplicate prevout tx fields", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx))
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx))

		_, err := PrevoutTxsForIntentFromPSBT(ptx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple prevout tx fields")
	})
}

func TestPrevoutTxsForArkTxFromPSBT(t *testing.T) {
	t.Run("validates through checkpoint input", func(t *testing.T) {
		sourceTx := newTestPrevoutTx(1)
		checkpoint := newTestCheckpointPSBT(t, sourceTx.TxHash(), 0)
		arkPtx := newTestPSBT(t, 1)
		arkPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = checkpoint.UnsignedTx.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevoutTxField, *sourceTx))

		prevoutTxs, err := PrevoutTxsForArkTxFromPSBT(arkPtx, []*psbt.Packet{checkpoint})
		require.NoError(t, err)
		require.Len(t, prevoutTxs, 1)
		require.Equal(t, sourceTx.TxHash(), prevoutTxs[0].TxHash())
	})

	t.Run("rejects source tx that does not match checkpoint input", func(t *testing.T) {
		sourceTx := newTestPrevoutTx(1)
		wrongSourceTx := newTestPrevoutTx(2)
		checkpoint := newTestCheckpointPSBT(t, sourceTx.TxHash(), 0)
		arkPtx := newTestPSBT(t, 1)
		arkPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = checkpoint.UnsignedTx.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevoutTxField, *wrongSourceTx))

		_, err := PrevoutTxsForArkTxFromPSBT(arkPtx, []*psbt.Packet{checkpoint})
		require.Error(t, err)
		require.Contains(t, err.Error(), "prevout tx hash mismatch")
	})

	t.Run("rejects checkpoint input output index out of source tx range", func(t *testing.T) {
		sourceTx := newTestPrevoutTx(1)
		checkpoint := newTestCheckpointPSBT(t, sourceTx.TxHash(), 42)
		arkPtx := newTestPSBT(t, 1)
		arkPtx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = checkpoint.UnsignedTx.TxHash()

		require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevoutTxField, *sourceTx))

		_, err := PrevoutTxsForArkTxFromPSBT(arkPtx, []*psbt.Packet{checkpoint})
		require.Error(t, err)
		require.Contains(t, err.Error(), "prevout tx output index out of range")
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

func newTestCheckpointPSBT(t *testing.T, sourceTxHash chainhash.Hash, sourceTxOutputIndex uint32) *psbt.Packet {
	t.Helper()

	ptx := newTestPSBT(t, 1)
	ptx.UnsignedTx.TxIn[0].PreviousOutPoint = wire.OutPoint{
		Hash:  sourceTxHash,
		Index: sourceTxOutputIndex,
	}
	ptx.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    1,
		PkScript: []byte{txscript.OP_TRUE},
	})

	return ptx
}
