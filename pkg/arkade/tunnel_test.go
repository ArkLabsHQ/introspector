package arkade

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestTunnelPreservesSelectedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		flags  int64
		mutate func(*Engine)
		ok     bool
	}{
		{name: "script and value", flags: TunnelScriptPubKey | TunnelValue, ok: true},
		{name: "script only ignores value", flags: TunnelScriptPubKey, mutate: func(vm *Engine) { vm.tx.TxOut[0].Value++ }, ok: true},
		{name: "value only ignores script", flags: TunnelValue, mutate: func(vm *Engine) { vm.tx.TxOut[0].PkScript = []byte{OP_FALSE} }, ok: true},
		{name: "changed script", flags: TunnelScriptPubKey, mutate: func(vm *Engine) { vm.tx.TxOut[0].PkScript = []byte{OP_FALSE} }},
		{name: "changed value", flags: TunnelValue, mutate: func(vm *Engine) { vm.tx.TxOut[0].Value++ }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm := tunnelTestVM(t)
			if test.mutate != nil {
				test.mutate(vm)
			}
			vm.SetStack(tunnelStack(0, test.flags))
			err := invokeOpcodeWithData(OP_TUNNEL, nil, vm)
			if test.ok {
				require.NoError(t, err)
				require.Equal(t, [][]byte{{1}}, vm.GetStack())
				return
			}
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

func TestTunnelRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stack [][]byte
	}{
		{name: "zero flags", stack: tunnelStack(0, 0)},
		{name: "unknown flags", stack: tunnelStack(0, 4)},
		{name: "negative output", stack: tunnelStack(-1, TunnelValue)},
		{name: "output out of range", stack: tunnelStack(1, TunnelValue)},
		{name: "asset exceptions", stack: [][]byte{nil, scriptNum(TunnelValue).Bytes(), {1}}},
		{name: "underflow"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm := tunnelTestVM(t)
			vm.SetStack(test.stack)
			requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation)
		})
	}
}

func tunnelSpec() *opcodeSpec {
	return &opcodeSpec{
		opcode: OP_TUNNEL,
		checkProperties: func(t *testing.T, c opcodeCheckContext) {
			t.Helper()
			require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
			require.Equal(t, c.before.condStack, c.after.condStack)
			if c.execErr != nil {
				requireScriptErrorCodeIn(t, c.execErr, txscript.ErrInvalidStackOperation, txscript.ErrNumberTooBig, txscript.ErrMinimalData)
				return
			}
			require.NotEmpty(t, c.after.GetStack())
			require.Equal(t, []byte{1}, c.after.GetStack()[len(c.after.GetStack())-1])
		},
		validVectors: []opcodeVector{{
			name:          "value",
			inputStack:    tunnelStack(0, TunnelValue),
			setupWorld:    func(w *opcodeWorld) { w.tx.TxOut[0].Value = w.prevouts[w.tx.TxIn[0].PreviousOutPoint].Value },
			expectedStack: [][]byte{{1}},
		}},
		invalidVectors: []opcodeVector{{name: "underflow", expectedError: txscript.ErrInvalidStackOperation}},
	}
}

func tunnelTestVM(t *testing.T) *Engine {
	t.Helper()

	outpoint := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	script := []byte{OP_1, 32, 1}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(10_000, script))

	base := txscript.NewMultiPrevOutFetcher(nil)
	base.AddPrevOut(outpoint, wire.NewTxOut(10_000, []byte{OP_TRUE}))
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxOut(wire.NewTxOut(10_000, script))

	return &Engine{
		tx:             *tx,
		txIdx:          0,
		prevOutFetcher: newTestArkPrevOutFetcher(base, map[wire.OutPoint]*wire.MsgTx{outpoint: arkTx}, map[wire.OutPoint]uint32{outpoint: 0}),
	}
}

func tunnelStack(outputIndex, flags int64) [][]byte {
	return [][]byte{scriptNum(outputIndex).Bytes(), scriptNum(flags).Bytes(), nil}
}
