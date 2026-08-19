package arkade

import (
	"bytes"
	"fmt"
	"math/bits"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type TunnelPurpose uint8

const (
	TunnelPurposeRegisterIntent TunnelPurpose = iota + 1
	TunnelPurposeFinalizationReplay
)

type TunnelSource struct {
	ScriptPubKey    []byte
	Value           int64
	Assets          map[asset.AssetId]uint64
	ExpiresAt       time.Time
	CommitmentTxids []string
	Spent           bool
	Swept           bool
	Unrolled        bool
}

type TunnelMapping struct {
	InputIndex     int
	SourceOutPoint wire.OutPoint
	OutputIndex    int
}

type TunnelContext struct {
	Purpose             TunnelPurpose
	Sources             map[wire.OutPoint]TunnelSource
	EvaluatedAt         time.Time
	RenewalWindow       time.Duration
	CompletionMargin    time.Duration
	RegisterExpireAt    time.Time
	HasOnchainOutputs   bool
	claimedInputs       map[int]TunnelMapping
	claimedOutputInputs map[int]int
}

func (c *TunnelContext) MappingForInput(inputIndex int) (TunnelMapping, bool) {
	if c == nil {
		return TunnelMapping{}, false
	}
	mapping, ok := c.claimedInputs[inputIndex]
	return mapping, ok
}

func opcodeTunnel(op *opcode, data []byte, vm *Engine) error {
	if vm.tunnelContext == nil {
		return tunnelError("missing tunnel context")
	}

	outputIndex, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if outputIndex < 0 || int64(outputIndex) >= int64(len(vm.tx.TxOut)) {
		return tunnelError("output index out of range")
	}

	if err := vm.tunnelContext.authorize(vm, int(outputIndex)); err != nil {
		return tunnelError(err.Error())
	}
	vm.dstack.PushBool(true)
	return nil
}

func (c *TunnelContext) authorize(vm *Engine, outputIndex int) error {
	if c.Purpose != TunnelPurposeRegisterIntent && c.Purpose != TunnelPurposeFinalizationReplay {
		return fmt.Errorf("invalid execution purpose")
	}
	if vm.txIdx < 0 || vm.txIdx >= len(vm.tx.TxIn) {
		return fmt.Errorf("input index out of range")
	}
	if c.HasOnchainOutputs {
		return fmt.Errorf("register intent contains on-chain outputs")
	}
	if c.Purpose == TunnelPurposeRegisterIntent &&
		(c.RenewalWindow <= 0 || c.CompletionMargin <= 0 || c.CompletionMargin >= c.RenewalWindow) {
		return fmt.Errorf("tunnel policy is disabled or invalid")
	}
	if c.claimedInputs == nil {
		c.claimedInputs = make(map[int]TunnelMapping)
	}
	if c.claimedOutputInputs == nil {
		c.claimedOutputInputs = make(map[int]int)
	}
	if _, exists := c.claimedInputs[vm.txIdx]; exists {
		return fmt.Errorf("input already tunneled")
	}
	if _, exists := c.claimedOutputInputs[outputIndex]; exists {
		return fmt.Errorf("output already claimed")
	}

	extensionIndex := -1
	for i, output := range vm.tx.TxOut {
		if !extension.IsExtension(output.PkScript) {
			continue
		}
		if extensionIndex >= 0 {
			return fmt.Errorf("multiple extension outputs")
		}
		extensionIndex = i
	}
	if extensionIndex != len(vm.tx.TxOut)-1 {
		return fmt.Errorf("extension output is not last")
	}
	if outputIndex == extensionIndex {
		return fmt.Errorf("selected output is an extension")
	}

	outpoint := vm.tx.TxIn[vm.txIdx].PreviousOutPoint
	source, ok := c.Sources[outpoint]
	if !ok {
		return fmt.Errorf("source is not an indexed VTXO")
	}
	if c.Purpose == TunnelPurposeRegisterIntent {
		if err := c.validateAdmission(source); err != nil {
			return err
		}
	}

	if vm.prevOutFetcher == nil {
		return fmt.Errorf("missing prevout fetcher")
	}
	prevout := vm.prevOutFetcher.FetchPrevOutput(outpoint)
	if prevout == nil || prevout.Value != source.Value {
		return fmt.Errorf("source value does not match prevout")
	}
	if !bytes.Equal(vm.prevOutFetcher.FetchVtxoPrevOutPkScript(outpoint), source.ScriptPubKey) {
		return fmt.Errorf("source script does not match prevout")
	}
	output := vm.tx.TxOut[outputIndex]
	if output.Value != source.Value || !bytes.Equal(output.PkScript, source.ScriptPubKey) {
		return fmt.Errorf("selected output does not preserve source")
	}

	inputAssets, outputAssets, err := tunnelAssetMaps(vm.assetPacket, vm.txIdx, outputIndex, len(vm.tx.TxIn), len(vm.tx.TxOut))
	if err != nil {
		return err
	}
	if !equalAssetMaps(inputAssets, source.Assets) {
		return fmt.Errorf("source assets do not match packet input")
	}
	if !equalAssetMaps(outputAssets, source.Assets) {
		return fmt.Errorf("selected output does not preserve source assets")
	}

	mapping := TunnelMapping{
		InputIndex:     vm.txIdx,
		SourceOutPoint: outpoint,
		OutputIndex:    outputIndex,
	}
	c.claimedInputs[vm.txIdx] = mapping
	c.claimedOutputInputs[outputIndex] = vm.txIdx
	return nil
}

func (c *TunnelContext) validateAdmission(source TunnelSource) error {
	if c.EvaluatedAt.IsZero() || c.RegisterExpireAt.IsZero() {
		return fmt.Errorf("missing authorization time or register expiry")
	}
	if source.Spent || source.Swept || source.Unrolled || len(source.CommitmentTxids) == 0 {
		return fmt.Errorf("source is not an eligible live off-chain VTXO")
	}
	if source.ExpiresAt.Before(c.EvaluatedAt.Add(c.CompletionMargin)) || source.ExpiresAt.After(c.EvaluatedAt.Add(c.RenewalWindow)) {
		return fmt.Errorf("source is outside the renewal window")
	}
	if c.RegisterExpireAt.After(source.ExpiresAt.Add(-c.CompletionMargin)) {
		return fmt.Errorf("register intent expires too late")
	}
	return nil
}

func tunnelAssetMaps(packet asset.Packet, inputIndex, outputIndex, inputCount, outputCount int) (map[asset.AssetId]uint64, map[asset.AssetId]uint64, error) {
	inputAssets := make(map[asset.AssetId]uint64)
	outputAssets := make(map[asset.AssetId]uint64)
	seen := make(map[asset.AssetId]struct{}, len(packet))

	for _, group := range packet {
		if group.AssetId == nil || group.ControlAsset != nil || len(group.Metadata) > 0 {
			return nil, nil, fmt.Errorf("asset packet is not a pure transfer")
		}
		id := *group.AssetId
		if _, exists := seen[id]; exists {
			return nil, nil, fmt.Errorf("asset packet contains duplicate asset groups")
		}
		seen[id] = struct{}{}

		var inputSum, outputSum uint64
		for _, input := range group.Inputs {
			if input.Type != asset.AssetInputTypeLocal || int(input.Vin) >= inputCount {
				return nil, nil, fmt.Errorf("asset packet contains a non-local or invalid input")
			}
			var carry uint64
			inputSum, carry = bits.Add64(inputSum, input.Amount, 0)
			if carry != 0 {
				return nil, nil, fmt.Errorf("asset input amount overflow")
			}
			if int(input.Vin) == inputIndex {
				amount, carry := bits.Add64(inputAssets[id], input.Amount, 0)
				if carry != 0 {
					return nil, nil, fmt.Errorf("source asset amount overflow")
				}
				inputAssets[id] = amount
			}
		}
		for _, output := range group.Outputs {
			if output.Type != asset.AssetOutputTypeLocal || int(output.Vout) >= outputCount {
				return nil, nil, fmt.Errorf("asset packet contains a non-local or invalid output")
			}
			var carry uint64
			outputSum, carry = bits.Add64(outputSum, output.Amount, 0)
			if carry != 0 {
				return nil, nil, fmt.Errorf("asset output amount overflow")
			}
			if int(output.Vout) == outputIndex {
				amount, carry := bits.Add64(outputAssets[id], output.Amount, 0)
				if carry != 0 {
					return nil, nil, fmt.Errorf("successor asset amount overflow")
				}
				outputAssets[id] = amount
			}
		}
		if inputSum != outputSum {
			return nil, nil, fmt.Errorf("asset packet does not conserve amounts")
		}
	}

	return inputAssets, outputAssets, nil
}

func equalAssetMaps(a, b map[asset.AssetId]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for id, amount := range a {
		if b[id] != amount {
			return false
		}
	}
	return true
}

func tunnelError(description string) error {
	return scriptError(txscript.ErrInvalidStackOperation, description)
}
