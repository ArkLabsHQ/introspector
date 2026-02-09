package application

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type Info struct {
	SignerPublicKey string
}

type OffchainTx struct {
	ArkTx       *psbt.Packet
	Checkpoints []*psbt.Packet
}

type Intent struct {
	Proof   intent.Proof
	Message intent.RegisterMessage
}

type BatchFinalization struct {
	Intent        Intent
	Forfeits      []*psbt.Packet
	ConnectorTree *tree.TxTree
	CommitmentTx  *psbt.Packet
}

type SignedBatchFinalization struct {
	Forfeits     []*psbt.Packet
	CommitmentTx *psbt.Packet
}

type Service interface {
	GetInfo(context.Context) (*Info, error)
	SubmitTx(context.Context, OffchainTx) (*OffchainTx, error)
	SubmitIntent(context.Context, Intent) (*psbt.Packet, error)
	SubmitFinalization(context.Context, BatchFinalization) (*SignedBatchFinalization, error)
}

type service struct {
	signer    signer
	publicKey string
}

func New(secretKey *btcec.PrivateKey) Service {
	publicKey := hex.EncodeToString(secretKey.PubKey().SerializeCompressed())
	return &service{signer{secretKey}, publicKey}
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{SignerPublicKey: s.publicKey}, nil
}

// TODO : do not rely on witness utxo to compute the prevout fetcher
func computePrevoutFetcher(ptx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for index, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("witness utxo is nil")
		}

		if len(ptx.UnsignedTx.TxIn) <= index {
			return nil, fmt.Errorf("input index out of range")
		}

		outpoint := ptx.UnsignedTx.TxIn[index].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}
