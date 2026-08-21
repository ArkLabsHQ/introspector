package arkade

import (
	"bytes"
	"maps"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

const (
	TunnelScriptPubKey = 1 << iota
	TunnelValue
	TunnelAssets
)

const tunnelFlags = TunnelScriptPubKey | TunnelValue | TunnelAssets

func opcodeTunnel(op *opcode, data []byte, vm *Engine) error {
	exceptionCount, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	remaining := int64(vm.dstack.Depth())
	if exceptionCount < 0 || remaining < 2 || int64(exceptionCount) > (remaining-2)/2 {
		return tunnelError("invalid asset exception count")
	}

	exceptions := make(map[asset.AssetId]struct{}, int(exceptionCount))
	for range int(exceptionCount) {
		txid, index, err := popAssetID(vm)
		if err != nil {
			return err
		}
		id := asset.AssetId{Txid: txid, Index: index}
		if _, exists := exceptions[id]; exists {
			return tunnelError("duplicate asset exception")
		}
		exceptions[id] = struct{}{}
	}

	flags, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if flags <= 0 || flags&^scriptNum(tunnelFlags) != 0 {
		return tunnelError("invalid tunnel flags")
	}
	if flags&TunnelAssets == 0 && len(exceptions) > 0 {
		return tunnelError("asset exceptions require asset tunneling")
	}

	outputIndex, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if outputIndex < 0 || int64(outputIndex) >= int64(len(vm.tx.TxOut)) {
		return tunnelError("output index out of range")
	}
	if vm.txIdx < 0 || vm.txIdx >= len(vm.tx.TxIn) {
		return tunnelError("input index out of range")
	}
	if vm.prevOutFetcher == nil {
		return tunnelError("missing prevout fetcher")
	}

	outpoint := vm.tx.TxIn[vm.txIdx].PreviousOutPoint
	output := vm.tx.TxOut[int(outputIndex)]
	if flags&TunnelScriptPubKey != 0 {
		script := vm.prevOutFetcher.FetchVtxoPrevOutPkScript(outpoint)
		if script == nil {
			return tunnelError("source script is missing")
		}
		if !bytes.Equal(script, output.PkScript) {
			return tunnelError("selected output does not preserve source script")
		}
	}
	if flags&TunnelValue != 0 {
		prevout := vm.prevOutFetcher.FetchPrevOutput(outpoint)
		if prevout == nil {
			return tunnelError("source prevout is missing")
		}
		if prevout.Value != output.Value {
			return tunnelError("selected output does not preserve source value")
		}
	}
	if flags&TunnelAssets != 0 {
		inputAssets, outputAssets, err := tunnelAssetMaps(
			vm.tx.TxHash(), vm.assetPacket, vm.txIdx, int(outputIndex), exceptions,
		)
		if err != nil {
			return err
		}
		if !maps.Equal(inputAssets, outputAssets) {
			return tunnelError("selected output does not preserve source assets")
		}
	}

	vm.dstack.PushBool(true)
	return nil
}

func tunnelAssetMaps(txHash chainhash.Hash, packet asset.Packet, inputIndex, outputIndex int, exceptions map[asset.AssetId]struct{}) (map[asset.AssetId]uint64, map[asset.AssetId]uint64, error) {
	inputAssets := make(map[asset.AssetId]uint64)
	outputAssets := make(map[asset.AssetId]uint64)
	if len(packet) == 0 {
		return inputAssets, outputAssets, nil
	}
	if _, err := asset.NewPacket([]asset.AssetGroup(packet)); err != nil {
		return nil, nil, tunnelError("invalid asset packet: " + err.Error())
	}

	for groupIndex, group := range packet {
		id, err := resolveAssetID(txHash, groupIndex, group)
		if err != nil {
			return nil, nil, err
		}
		if _, excluded := exceptions[id]; excluded {
			continue
		}
		for _, input := range group.Inputs {
			if input.Type == asset.AssetInputTypeLocal && int(input.Vin) == inputIndex {
				inputAssets[id] = input.Amount
			}
		}
		for _, output := range group.Outputs {
			if output.Type == asset.AssetOutputTypeLocal && int(output.Vout) == outputIndex {
				outputAssets[id] = output.Amount
			}
		}
	}

	return inputAssets, outputAssets, nil
}

func tunnelError(description string) error {
	return scriptError(txscript.ErrInvalidStackOperation, description)
}
