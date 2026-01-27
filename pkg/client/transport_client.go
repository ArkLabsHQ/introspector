package client

import (
	"context"

	introspectorv1 "github.com/ArkLabsHQ/introspector/api-spec/protobuf/gen/introspector/v1"
	"google.golang.org/grpc"
)

type Info struct {
	Version         string
	SignerPublicKey string
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	SubmitTx(ctx context.Context, tx string, checkpoints []string) (signedTx string, signedCheckpoints []string, err error)
}

// grpcClient implements TransportClient using gRPC
type grpcClient struct {
	client introspectorv1.IntrospectorServiceClient
}

// NewGRPCClient creates a new gRPC-based transport client
func NewGRPCClient(conn *grpc.ClientConn) TransportClient {
	return &grpcClient{
		client: introspectorv1.NewIntrospectorServiceClient(conn),
	}
}

// GetInfo retrieves service information
func (c *grpcClient) GetInfo(ctx context.Context) (*Info, error) {
	req := &introspectorv1.GetInfoRequest{}
	resp, err := c.client.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}

	return &Info{
		Version:         resp.GetVersion(),
		SignerPublicKey: resp.GetSignerPubkey(),
	}, nil
}

// SubmitTx submits a transaction for signing
func (c *grpcClient) SubmitTx(ctx context.Context, tx string, checkpoints []string) (signedTx string, signedCheckpoints []string, err error) {
	req := &introspectorv1.SubmitTxRequest{
		ArkTx:         tx,
		CheckpointTxs: checkpoints,
	}

	resp, err := c.client.SubmitTx(ctx, req)
	if err != nil {
		return "", nil, err
	}

	return resp.GetSignedArkTx(), resp.GetSignedCheckpointTxs(), nil
}
