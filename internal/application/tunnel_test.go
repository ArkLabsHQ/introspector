package application

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/arkade"
	sdkclient "github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestTunnelIntentMessageCommitment(t *testing.T) {
	t.Parallel()

	rawMessage := `{ "type": "register", "expire_at": 1800000000 }`
	message := &intent.RegisterMessage{}
	require.NoError(t, message.Decode(rawMessage))
	outpoint := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 2}
	proof, err := intent.New(rawMessage, []intent.Input{{
		OutPoint:    &outpoint,
		WitnessUtxo: wire.NewTxOut(10_000, []byte{txscript.OP_TRUE}),
	}}, []*wire.TxOut{wire.NewTxOut(10_000, []byte{txscript.OP_TRUE})})
	require.NoError(t, err)

	request := Intent{
		Proof:          *proof,
		Message:        message,
		EncodedMessage: rawMessage,
	}
	require.NoError(t, validateIntentMessageCommitment(request))

	request.EncodedMessage = `{"type":"register","expire_at":1800000001}`
	require.ErrorContains(t, validateIntentMessageCommitment(request), "does not match")
}

func TestScriptHasTunnelIgnoresPushedBytes(t *testing.T) {
	t.Parallel()

	found, err := scriptHasTunnel([]byte{txscript.OP_DATA_1, arkade.OP_TUNNEL})
	require.NoError(t, err)
	require.False(t, found)

	found, err = scriptHasTunnel([]byte{arkade.OP_TUNNEL})
	require.NoError(t, err)
	require.True(t, found)

	_, err = scriptHasTunnel([]byte{txscript.OP_DATA_2, arkade.OP_TUNNEL})
	require.Error(t, err)
}

func TestTunnelPolicyValidation(t *testing.T) {
	t.Parallel()

	require.NoError(t, (TunnelPolicy{}).Validate())
	require.NoError(t, (TunnelPolicy{RenewalWindow: time.Hour, CompletionMargin: time.Minute}).Validate())
	require.Error(t, (TunnelPolicy{RenewalWindow: time.Hour}).Validate())
	require.Error(t, (TunnelPolicy{RenewalWindow: time.Hour, CompletionMargin: time.Hour}).Validate())
}

func TestTunnelPolicyCoversArkdSession(t *testing.T) {
	t.Parallel()

	policy := TunnelPolicy{RenewalWindow: time.Hour, CompletionMargin: 10 * time.Minute}
	require.NoError(t, validateTunnelPolicyAgainstArkdInfo(policy, &sdkclient.Info{
		SessionDuration:          300,
		ScheduledSessionDuration: 600,
	}))
	require.Error(t, validateTunnelPolicyAgainstArkdInfo(policy, &sdkclient.Info{
		ScheduledSessionDuration: 601,
	}))
}

func TestSubmitIntentExecutesTunnelWithIndexedSource(t *testing.T) {
	signerKey := newResolverPrivateKey(t)
	tunnelScript := []byte{txscript.OP_0, arkade.OP_TUNNEL}
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(tunnelScript),
	)
	owned := newIntentVtxo(t, tweaked)
	ptx := newIntentProof(
		t, []intentVtxo{owned, owned},
		arkade.EmulatorEntry{Vin: 1, Script: tunnelScript},
	)
	ptx.UnsignedTx.TxOut[0].Value = 2_000

	now := time.Now()
	message := &intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		ExpireAt:    now.Add(30 * time.Minute).Unix(),
	}
	encodedMessage, err := message.Encode()
	require.NoError(t, err)
	firstInput := ptx.UnsignedTx.TxIn[1]
	expected, err := intent.New(encodedMessage, []intent.Input{{
		OutPoint:    &firstInput.PreviousOutPoint,
		Sequence:    firstInput.Sequence,
		WitnessUtxo: ptx.Inputs[1].WitnessUtxo,
	}}, nil)
	require.NoError(t, err)
	ptx.UnsignedTx.TxIn[0].PreviousOutPoint = expected.UnsignedTx.TxIn[0].PreviousOutPoint

	indexerClient := &tunnelIndexer{vtxos: []types.Vtxo{{
		Outpoint:        types.Outpoint{Txid: firstInput.PreviousOutPoint.Hash.String(), VOut: firstInput.PreviousOutPoint.Index},
		Script:          hex.EncodeToString(owned.pkScript),
		Amount:          2_000,
		CommitmentTxids: []string{"commitment"},
		ExpiresAt:       now.Add(90 * time.Minute),
	}}}
	svc := &service{
		signer:        signer{signerKey},
		indexerClient: indexerClient,
		tunnelPolicy: TunnelPolicy{
			RenewalWindow:    2 * time.Hour,
			CompletionMargin: 30 * time.Minute,
		},
	}
	request := Intent{
		Proof:          intent.Proof{Packet: *ptx},
		Message:        message,
		EncodedMessage: encodedMessage,
	}
	signed, err := svc.SubmitIntent(t.Context(), request)
	require.NoError(t, err)
	require.NotEmpty(t, signed.Inputs[1].TaprootScriptSpendSig)
	require.Equal(t, 1, indexerClient.calls)

	request.Proof = intent.Proof{Packet: *signed}
	associations, err := getSignedInputAssociations(request.Proof.Packet, signer{signerKey}, nil)
	require.NoError(t, err)
	require.NoError(t, svc.replayTunnelAuthorizations(t.Context(), request, associations))
	require.True(t, associations[firstInput.PreviousOutPoint].tunneled)

	commitmentTx := wire.NewMsgTx(3)
	commitmentTx.AddTxIn(wire.NewTxIn(&firstInput.PreviousOutPoint, nil, nil))
	commitmentTx.AddTxOut(wire.NewTxOut(1_000, []byte{txscript.OP_TRUE}))
	commitment, err := psbt.NewFromUnsignedTx(commitmentTx)
	require.NoError(t, err)
	commitment.Inputs[0].WitnessUtxo = signed.Inputs[1].WitnessUtxo
	commitment.Inputs[0].TaprootLeafScript = signed.Inputs[1].TaprootLeafScript

	finalized, err := svc.SubmitFinalization(t.Context(), BatchFinalization{
		Intent:       request,
		CommitmentTx: commitment,
	})
	require.ErrorContains(t, err, "cannot sign a commitment transaction")
	require.Nil(t, finalized)
	require.Empty(t, commitment.Inputs[0].TaprootScriptSpendSig)
}

type tunnelIndexer struct {
	indexer.Indexer
	vtxos []types.Vtxo
	calls int
}

func (m *tunnelIndexer) GetVtxos(context.Context, ...indexer.GetVtxosRequestOption) (*indexer.VtxosResponse, error) {
	m.calls++
	return &indexer.VtxosResponse{Vtxos: m.vtxos}, nil
}

func (m *tunnelIndexer) GetCommitmentTx(context.Context, string) (*indexer.CommitmentTx, error) {
	return &indexer.CommitmentTx{}, nil
}
