package arkade

import (
	"math"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestTunnelExactContinuation(t *testing.T) {
	t.Parallel()

	vm, ctx := tunnelTestVM(t, nil)
	vm.SetStack([][]byte{nil})
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
	require.Equal(t, [][]byte{{1}}, vm.GetStack())

	require.True(t, ctx.InputWasTunneled(0))
}

func TestTunnelAdmissionBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Engine, *TunnelContext)
		ok     bool
	}{
		{name: "completion margin boundary", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.ExpiresAt = ctx.EvaluatedAt.Add(ctx.CompletionMargin)
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
			ctx.RegisterExpireAt = ctx.EvaluatedAt
		}, ok: true},
		{name: "renewal window boundary", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.ExpiresAt = ctx.EvaluatedAt.Add(ctx.RenewalWindow)
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
		}, ok: true},
		{name: "too early", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.ExpiresAt = ctx.EvaluatedAt.Add(ctx.RenewalWindow + time.Second)
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
		}},
		{name: "insufficient completion time", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.ExpiresAt = ctx.EvaluatedAt.Add(ctx.CompletionMargin - time.Second)
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
		}},
		{name: "disabled policy", mutate: func(vm *Engine, ctx *TunnelContext) { ctx.RenewalWindow = 0 }},
		{name: "late register expiry", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			ctx.RegisterExpireAt = source.ExpiresAt.Add(-ctx.CompletionMargin + time.Second)
		}},
		{name: "spent", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.Spent = true
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
		}},
		{name: "note", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.CommitmentTxids = nil
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
		}},
		{name: "onchain output marking", mutate: func(vm *Engine, ctx *TunnelContext) { ctx.HasOnchainOutputs = true }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm, ctx := tunnelTestVM(t, nil)
			test.mutate(vm, ctx)
			vm.SetStack([][]byte{nil})
			err := invokeOpcodeWithData(OP_TUNNEL, nil, vm)
			if test.ok {
				require.NoError(t, err)
				return
			}
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

func TestTunnelRejectsChangedContinuation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Engine, *TunnelContext)
	}{
		{name: "value", mutate: func(vm *Engine, ctx *TunnelContext) { vm.tx.TxOut[0].Value++ }},
		{name: "script", mutate: func(vm *Engine, ctx *TunnelContext) { vm.tx.TxOut[0].PkScript = []byte{txscript.OP_TRUE} }},
		{name: "source value", mutate: func(vm *Engine, ctx *TunnelContext) {
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.Value++
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
		}},
		{name: "extension not last", mutate: func(vm *Engine, ctx *TunnelContext) {
			vm.tx.TxOut[0], vm.tx.TxOut[1] = vm.tx.TxOut[1], vm.tx.TxOut[0]
		}},
		{name: "multiple extensions", mutate: func(vm *Engine, ctx *TunnelContext) {
			vm.tx.TxOut = append(vm.tx.TxOut, vm.tx.TxOut[1])
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm, ctx := tunnelTestVM(t, nil)
			test.mutate(vm, ctx)
			vm.SetStack([][]byte{nil})
			requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation)
		})
	}
}

func TestTunnelPreservesAssetsAndRequiresPureTransfer(t *testing.T) {
	t.Parallel()

	id := asset.AssetId{Txid: chainhash.Hash{1}, Index: 2}
	pureTransfer := asset.Packet{{
		AssetId: &id,
		Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
		Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 7}},
	}}

	tests := []struct {
		name   string
		packet asset.Packet
		assets map[asset.AssetId]uint64
		ok     bool
	}{
		{name: "exact", packet: pureTransfer, assets: map[asset.AssetId]uint64{id: 7}, ok: true},
		{name: "missing source asset", packet: pureTransfer},
		{name: "changed amount", packet: pureTransfer, assets: map[asset.AssetId]uint64{id: 8}},
		{name: "issuance", packet: asset.Packet{{Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 7}}}}},
		{name: "burn", packet: asset.Packet{{AssetId: &id, Inputs: []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}}}}, assets: map[asset.AssetId]uint64{id: 7}},
		{name: "metadata", packet: asset.Packet{{
			AssetId:  &id,
			Inputs:   pureTransfer[0].Inputs,
			Outputs:  pureTransfer[0].Outputs,
			Metadata: []asset.Metadata{{Key: []byte("k"), Value: []byte("v")}},
		}}, assets: map[asset.AssetId]uint64{id: 7}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm, ctx := tunnelTestVM(t, test.packet)
			source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
			source.Assets = test.assets
			ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
			vm.SetStack([][]byte{nil})
			err := invokeOpcodeWithData(OP_TUNNEL, nil, vm)
			if test.ok {
				require.NoError(t, err)
				return
			}
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

func TestTunnelAssetConservationDoesNotOverflow(t *testing.T) {
	t.Parallel()

	id := asset.AssetId{Txid: chainhash.Hash{1}, Index: 2}
	packet := asset.Packet{{
		AssetId: &id,
		Inputs: []asset.AssetInput{
			{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: math.MaxUint64},
			{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 1},
		},
		Outputs: []asset.AssetOutput{
			{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: math.MaxUint64},
			{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 1},
		},
	}}

	inputs, outputs, err := tunnelAssetMaps(packet, 0, 0, 2, 2)
	require.NoError(t, err)
	require.Equal(t, map[asset.AssetId]uint64{id: math.MaxUint64}, inputs)
	require.Equal(t, inputs, outputs)
}

func TestTunnelClaimsAreOneToOne(t *testing.T) {
	t.Parallel()

	vm, ctx := tunnelTestVM(t, nil)
	vm.SetStack([][]byte{nil})
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
	vm.SetStack([][]byte{nil})
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation)

	otherOutpoint := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}
	vm.tx.TxIn = append(vm.tx.TxIn, wire.NewTxIn(&otherOutpoint, nil, nil))
	source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
	ctx.Sources[otherOutpoint] = source
	base := vm.prevOutFetcher.(*testArkPrevOutFetcher).PrevOutputFetcher.(*txscript.MultiPrevOutFetcher)
	base.AddPrevOut(otherOutpoint, wire.NewTxOut(source.Value, source.ScriptPubKey))
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxOut(wire.NewTxOut(source.Value, source.ScriptPubKey))
	fetcher := vm.prevOutFetcher.(*testArkPrevOutFetcher)
	fetcher.arkTxs[otherOutpoint] = arkTx
	fetcher.prevoutIdxs[otherOutpoint] = 0

	vm.txIdx = 1
	vm.SetStack([][]byte{nil})
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation)
}

func TestTunnelFinalizationReplayUsesDeterministicChecksOnly(t *testing.T) {
	t.Parallel()

	vm, ctx := tunnelTestVM(t, nil)
	ctx.Purpose = TunnelPurposeFinalizationReplay
	ctx.RenewalWindow = 0
	ctx.CompletionMargin = 0
	ctx.RegisterExpireAt = time.Time{}
	source := ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint]
	source.Spent = true
	ctx.Sources[vm.tx.TxIn[0].PreviousOutPoint] = source
	vm.SetStack([][]byte{nil})
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
}

func tunnelTestVM(t *testing.T, packet asset.Packet) (*Engine, *TunnelContext) {
	t.Helper()

	now := time.Unix(1_800_000_000, 0)
	outpoint := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	script := []byte{txscript.OP_1, 32}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(10_000, script))
	emulatorPacket, err := NewPacket(EmulatorEntry{Vin: 0, Script: []byte{txscript.OP_TRUE}})
	require.NoError(t, err)
	extensionOutput, err := (extension.Extension{emulatorPacket}).TxOut()
	require.NoError(t, err)
	tx.AddTxOut(extensionOutput)

	base := txscript.NewMultiPrevOutFetcher(nil)
	base.AddPrevOut(outpoint, wire.NewTxOut(10_000, script))
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxOut(wire.NewTxOut(10_000, script))
	fetcher := newTestArkPrevOutFetcher(
		base,
		map[wire.OutPoint]*wire.MsgTx{outpoint: arkTx},
		map[wire.OutPoint]uint32{outpoint: 0},
	)
	ctx := &TunnelContext{
		Purpose:          TunnelPurposeRegisterIntent,
		EvaluatedAt:      now,
		RenewalWindow:    2 * time.Hour,
		CompletionMargin: 30 * time.Minute,
		RegisterExpireAt: now.Add(45 * time.Minute),
		Sources: map[wire.OutPoint]TunnelSource{
			outpoint: {
				ScriptPubKey:    script,
				Value:           10_000,
				ExpiresAt:       now.Add(90 * time.Minute),
				CommitmentTxids: []string{"commitment"},
			},
		},
	}
	return &Engine{
		tx:             *tx,
		txIdx:          0,
		prevOutFetcher: fetcher,
		assetPacket:    packet,
		tunnelContext:  ctx,
	}, ctx
}
