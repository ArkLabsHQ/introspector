package application

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
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
	Close()
}

type service struct {
	signer     signer
	publicKey  string
	arkdClient client.TransportClient
	arkdPubKey *btcec.PublicKey
}

func New(ctx context.Context, secretKey *btcec.PrivateKey, arkdURL string) (Service, error) {
	publicKey := hex.EncodeToString(secretKey.PubKey().SerializeCompressed())

	arkdClient, err := grpcclient.NewClient(arkdURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
	}

	arkdInfo, err := arkdClient.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arkd info: %w", err)
	}
	if arkdInfo == nil {
		return nil, fmt.Errorf("arkd info is required")
	}
	if arkdInfo.SignerPubKey == "" {
		return nil, fmt.Errorf("arkd info does not include signer pubkey")
	}

	decodedKey, err := hex.DecodeString(arkdInfo.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode arkd signer pubkey: %w", err)
	}

	arkdPubKey, err := btcec.ParsePubKey(decodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse arkd signer pubkey: %w", err)
	}

	return &service{
		signer:     signer{secretKey},
		publicKey:  publicKey,
		arkdClient: arkdClient,
		arkdPubKey: arkdPubKey,
	}, nil
}

func (s *service) Close() {
	s.arkdClient.Close()
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{SignerPublicKey: s.publicKey}, nil
}
