package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	arkintent "github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type TunnelPolicy struct {
	RenewalWindow    time.Duration
	CompletionMargin time.Duration
}

func (p TunnelPolicy) Enabled() bool {
	return p.RenewalWindow > 0 && p.CompletionMargin > 0
}

func (p TunnelPolicy) Validate() error {
	if p.RenewalWindow == 0 && p.CompletionMargin == 0 {
		return nil
	}
	if p.RenewalWindow <= 0 || p.CompletionMargin <= 0 || p.CompletionMargin >= p.RenewalWindow {
		return fmt.Errorf("tunnel completion margin must be positive and smaller than the renewal window")
	}
	return nil
}

func (s *service) tunnelContextForIntent(ctx context.Context, request Intent, packet arkade.EmulatorPacket, evaluatedAt time.Time) (*arkade.TunnelContext, error) {
	tunnelInputs := make([]wire.OutPoint, 0)
	for _, entry := range packet {
		hasTunnel, err := scriptHasTunnel(entry.Script)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect arkade script for input %d: %w", entry.Vin, err)
		}
		if !hasTunnel {
			continue
		}
		inputIndex := int(entry.Vin)
		if inputIndex > 0 && inputIndex < len(request.Proof.UnsignedTx.TxIn) {
			tunnelInputs = append(tunnelInputs, request.Proof.UnsignedTx.TxIn[inputIndex].PreviousOutPoint)
		}
	}
	if len(tunnelInputs) == 0 {
		return nil, nil
	}

	message, ok := request.Message.(*arkintent.RegisterMessage)
	if !ok {
		return nil, nil
	}
	tunnelContext := &arkade.TunnelContext{
		Purpose:           arkade.TunnelPurposeRegisterIntent,
		EvaluatedAt:       evaluatedAt,
		RenewalWindow:     s.tunnelPolicy.RenewalWindow,
		CompletionMargin:  s.tunnelPolicy.CompletionMargin,
		HasOnchainOutputs: len(message.OnchainOutputIndexes) > 0,
	}
	if message.ExpireAt > 0 {
		tunnelContext.RegisterExpireAt = time.Unix(message.ExpireAt, 0)
	}
	if !s.tunnelPolicy.Enabled() {
		return tunnelContext, nil
	}

	sources, err := s.getTunnelSources(ctx, tunnelInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to load tunnel sources: %w", err)
	}
	tunnelContext.Sources = sources
	return tunnelContext, nil
}

func scriptHasTunnel(script []byte) (bool, error) {
	tokenizer := arkade.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		if tokenizer.Opcode() == arkade.OP_TUNNEL {
			return true, nil
		}
	}
	return false, tokenizer.Err()
}

func (s *service) getTunnelSources(ctx context.Context, outpoints []wire.OutPoint) (map[wire.OutPoint]arkade.TunnelSource, error) {
	if s.indexerClient == nil {
		return nil, fmt.Errorf("arkd indexer client is not configured")
	}
	requested := make(map[wire.OutPoint]struct{}, len(outpoints))
	sdkOutpoints := make([]types.Outpoint, 0, len(outpoints))
	for _, outpoint := range outpoints {
		if _, exists := requested[outpoint]; exists {
			continue
		}
		requested[outpoint] = struct{}{}
		sdkOutpoints = append(sdkOutpoints, types.Outpoint{Txid: outpoint.Hash.String(), VOut: outpoint.Index})
	}
	option := indexer.GetVtxosRequestOption{}
	if err := option.WithOutpoints(sdkOutpoints); err != nil {
		return nil, err
	}
	response, err := s.indexerClient.GetVtxos(withClientVersion(ctx, s.clientVersion), option)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("indexer returned no response")
	}

	sources := make(map[wire.OutPoint]arkade.TunnelSource, len(response.Vtxos))
	for _, vtxo := range response.Vtxos {
		hash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, fmt.Errorf("invalid source txid %q: %w", vtxo.Txid, err)
		}
		outpoint := wire.OutPoint{Hash: *hash, Index: vtxo.VOut}
		if _, ok := requested[outpoint]; !ok {
			return nil, fmt.Errorf("indexer returned unrequested VTXO %s", outpoint)
		}
		if _, exists := sources[outpoint]; exists {
			return nil, fmt.Errorf("indexer returned duplicate VTXO %s", outpoint)
		}
		if vtxo.Amount > math.MaxInt64 {
			return nil, fmt.Errorf("source value exceeds int64")
		}
		script, err := hex.DecodeString(vtxo.Script)
		if err != nil {
			return nil, fmt.Errorf("invalid source script: %w", err)
		}
		assets := make(map[asset.AssetId]uint64, len(vtxo.Assets))
		for _, sourceAsset := range vtxo.Assets {
			id, err := asset.NewAssetIdFromString(sourceAsset.AssetId)
			if err != nil {
				return nil, fmt.Errorf("invalid source asset ID: %w", err)
			}
			if _, exists := assets[*id]; exists {
				return nil, fmt.Errorf("duplicate source asset %s", sourceAsset.AssetId)
			}
			assets[*id] = sourceAsset.Amount
		}
		sources[outpoint] = arkade.TunnelSource{
			ScriptPubKey:    script,
			Value:           int64(vtxo.Amount),
			Assets:          assets,
			ExpiresAt:       vtxo.ExpiresAt,
			CommitmentTxids: append([]string(nil), vtxo.CommitmentTxids...),
			Spent:           vtxo.Spent,
			Swept:           vtxo.Swept,
			Unrolled:        vtxo.Unrolled,
		}
	}
	return sources, nil
}

func (s *service) replayTunnelAuthorizations(request Intent, signedInputs map[wire.OutPoint]signedInputAssociation) error {
	packet, err := arkade.FindEmulatorPacket(request.Proof.UnsignedTx)
	if err != nil {
		return err
	}
	tunnelEntries := make([]arkade.EmulatorEntry, 0)
	for _, entry := range packet {
		inputIndex := int(entry.Vin)
		if inputIndex <= 0 || inputIndex >= len(request.Proof.UnsignedTx.TxIn) {
			continue
		}
		outpoint := request.Proof.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if _, signed := signedInputs[outpoint]; !signed {
			continue
		}
		hasTunnel, err := scriptHasTunnel(entry.Script)
		if err != nil {
			return err
		}
		if hasTunnel {
			tunnelEntries = append(tunnelEntries, entry)
		}
	}
	if len(tunnelEntries) == 0 {
		return nil
	}

	message, ok := request.Message.(*arkintent.RegisterMessage)
	if !ok {
		return fmt.Errorf("tunnel authorization is not a register intent")
	}
	prevOutFetcher, err := prevOutFetcherForIntent(&request.Proof.Packet)
	if err != nil {
		return err
	}
	tunnelContext := &arkade.TunnelContext{
		Purpose:           arkade.TunnelPurposeFinalizationReplay,
		HasOnchainOutputs: len(message.OnchainOutputIndexes) > 0,
	}
	budget := arkade.NewComputeBudgetWithLimits(arkade.AggregateComputeLimits(s.computeLimits))
	for _, entry := range tunnelEntries {
		inputIndex := int(entry.Vin)
		outpoint := request.Proof.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		association := signedInputs[outpoint]
		if err := association.script.Execute(
			request.Proof.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			arkade.WithExactComputeLimits(s.computeLimits),
			arkade.WithComputeBudget(budget),
			arkade.WithTunnelContext(tunnelContext),
		); err != nil {
			return fmt.Errorf("input %d: %w", inputIndex, err)
		}
		if tunnelContext.InputWasTunneled(inputIndex) {
			association.tunneled = true
			signedInputs[outpoint] = association
		}
	}
	return nil
}
