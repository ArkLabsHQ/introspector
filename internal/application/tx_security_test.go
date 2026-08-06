package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// finalizingArkdClient lets a test drive the arkd finalization branch of
// SubmitTx, which the shared mock deliberately panics on.
type finalizingArkdClient struct {
	*mockArkdClient
	arkTx       string
	checkpoints []string
}

func (c *finalizingArkdClient) SubmitTx(
	context.Context, string, []string,
) (string, string, []string, error) {
	return "final-txid", c.arkTx, c.checkpoints, nil
}

// submitTxHarness builds a complete, self consistent ark tx + checkpoint pair
// so that individual bindings can be broken one at a time.
type submitTxHarness struct {
	svc        *service
	arkPtx     *psbt.Packet
	checkpoint *psbt.Packet
}

// taprootLeaf builds a single closure vtxo script and returns everything needed
// to both fund and spend it.
func taprootLeaf(t *testing.T, pubkeys ...*btcec.PublicKey) (*psbt.TaprootTapLeafScript, []byte) {
	t.Helper()

	closure := arkscript.MultisigClosure{PubKeys: pubkeys}
	vtxoScript := arkscript.TapscriptsVtxoScript{
		Closures: []arkscript.Closure{&closure},
	}

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	tapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(tapscript).TapHash())
	require.NoError(t, err)

	pkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)

	return &psbt.TaprootTapLeafScript{
		ControlBlock: merkleProof.ControlBlock,
		Script:       merkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}, pkScript
}

// newSubmitTxHarness wires an ark tx spending a checkpoint output. arkClosure
// and checkpointClosure select which pubkeys guard each leaf.
func newSubmitTxHarness(
	t *testing.T,
	arkClosure func(tweaked *btcec.PublicKey, alice, arkd *btcec.PublicKey) []*btcec.PublicKey,
	checkpointClosure func(tweaked *btcec.PublicKey, alice, arkd *btcec.PublicKey) []*btcec.PublicKey,
) *submitTxHarness {
	t.Helper()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes),
	)

	cpLeaf, cpInputPkScript := taprootLeaf(
		t, checkpointClosure(tweaked, aliceKey.PubKey(), arkdKey.PubKey())...,
	)
	arkLeaf, cpOutputPkScript := taprootLeaf(
		t, arkClosure(tweaked, aliceKey.PubKey(), arkdKey.PubKey())...,
	)

	// checkpoint spends a vtxo and pays the script the ark tx will spend
	cpTx := wire.NewMsgTx(2)
	cpTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{7}, Index: 0},
	})
	cpTx.AddTxOut(&wire.TxOut{Value: 9_500, PkScript: cpOutputPkScript})

	checkpoint, err := psbt.NewFromUnsignedTx(cpTx)
	require.NoError(t, err)
	checkpoint.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 10_000, PkScript: cpInputPkScript}
	checkpoint.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{cpLeaf}

	// ark tx spends the checkpoint output
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: checkpoint.UnsignedTx.TxHash(), Index: 0},
	})
	arkTx.AddTxOut(&wire.TxOut{Value: 9_000, PkScript: cpOutputPkScript})

	arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
	require.NoError(t, err)
	arkPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 9_500, PkScript: cpOutputPkScript}
	arkPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{arkLeaf}

	packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: arkadeScriptBytes})
	require.NoError(t, err)

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)
	arkPtx.UnsignedTx.AddTxOut(txOut)
	arkPtx.Outputs = append(arkPtx.Outputs, psbt.POutput{})

	return &submitTxHarness{
		svc: &service{
			signer:        signer{secretKey: signerKey},
			arkdPubKey:    arkdKey.PubKey(),
			computeLimits: arkade.DefaultComputeLimits(),
		},
		arkPtx:     arkPtx,
		checkpoint: checkpoint,
	}
}

func (h *submitTxHarness) submit(t *testing.T) (*OffchainTx, error) {
	t.Helper()

	return h.svc.SubmitTx(t.Context(), OffchainTx{
		ArkTx:       h.arkPtx,
		Checkpoints: []*psbt.Packet{h.checkpoint},
	})
}

// tweakedAliceArkd keeps the emulator from being the finalizer, so SubmitTx
// returns before ever contacting arkd.
func tweakedAliceArkd(tweaked, alice, arkd *btcec.PublicKey) []*btcec.PublicKey {
	return []*btcec.PublicKey{tweaked, alice, arkd}
}

func tweakedArkd(tweaked, _, arkd *btcec.PublicKey) []*btcec.PublicKey {
	return []*btcec.PublicKey{tweaked, arkd}
}

func aliceArkd(_, alice, arkd *btcec.PublicKey) []*btcec.PublicKey {
	return []*btcec.PublicKey{alice, arkd}
}

// TestSubmitTxBindsCheckpointToArkInput proves the checkpoint accompanying an
// ark input is bound to that input before the emulator signs it: its input 0
// leaf must be guarded by the same arkade tweaked key that the executed script
// authorises, and its output must match the witness utxo the ark input asserts.
func TestSubmitTxBindsCheckpointToArkInput(t *testing.T) {
	t.Run("baseline consistent request is signed", func(t *testing.T) {
		h := newSubmitTxHarness(t, tweakedAliceArkd, tweakedArkd)

		res, err := h.submit(t)
		require.NoError(t, err)
		require.Len(t, res.Checkpoints, 1)
		require.Len(t, res.Checkpoints[0].Inputs[0].TaprootScriptSpendSig, 1)
	})

	t.Run("checkpoint leaf not guarded by the arkade key is rejected", func(t *testing.T) {
		h := newSubmitTxHarness(t, tweakedAliceArkd, aliceArkd)

		_, err := h.submit(t)
		require.Error(t, err)
		require.ErrorContains(t, err, "checkpoint")
	})

	t.Run("ark input witness utxo not matching checkpoint output is rejected", func(t *testing.T) {
		h := newSubmitTxHarness(t, tweakedAliceArkd, tweakedArkd)
		// claim a far larger amount than the checkpoint actually pays
		h.arkPtx.Inputs[0].WitnessUtxo.Value = 100_000_000

		_, err := h.submit(t)
		require.Error(t, err)
		require.ErrorContains(t, err, "mismatch")
	})
}

// TestSubmitTxHandlesMalformedArkdCheckpointResponse proves a missing or
// input-less checkpoint in arkd's response is reported as an error instead of
// panicking the request after the emulator has already signed.
func TestSubmitTxHandlesMalformedArkdCheckpointResponse(t *testing.T) {
	newFinalizerHarness := func(t *testing.T) *submitTxHarness {
		t.Helper()
		// tweakedArkd on the ark leaf makes the emulator the finalizer
		return newSubmitTxHarness(t, tweakedArkd, tweakedArkd)
	}

	t.Run("missing checkpoint in arkd response", func(t *testing.T) {
		h := newFinalizerHarness(t)
		h.svc.arkdClient = &finalizingArkdClient{
			mockArkdClient: &mockArkdClient{},
			arkTx:          encodePacket(t, h.arkPtx),
			checkpoints:    nil,
		}

		require.NotPanics(t, func() {
			_, err := h.submit(t)
			require.Error(t, err)
			require.ErrorContains(t, err, "checkpoint")
		})
	})

	t.Run("checkpoint without inputs in arkd response", func(t *testing.T) {
		h := newFinalizerHarness(t)

		// same txid as the submitted checkpoint but stripped of psbt inputs
		empty, err := psbt.NewFromUnsignedTx(h.checkpoint.UnsignedTx.Copy())
		require.NoError(t, err)
		empty.Inputs = nil

		h.svc.arkdClient = &finalizingArkdClient{
			mockArkdClient: &mockArkdClient{},
			arkTx:          encodePacket(t, h.arkPtx),
			checkpoints:    []string{encodePacket(t, empty)},
		}

		require.NotPanics(t, func() {
			_, err := h.submit(t)
			require.Error(t, err)
			require.ErrorContains(t, err, "checkpoint")
		})
	})
}

func encodePacket(t *testing.T, ptx *psbt.Packet) string {
	t.Helper()

	encoded, err := ptx.B64Encode()
	require.NoError(t, err)

	return encoded
}

func TestValidateCheckpointBindingRejectsEmptyCheckpoint(t *testing.T) {
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxIn(&wire.TxIn{})
	arkTx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})

	arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
	require.NoError(t, err)
	arkPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2_000, PkScript: []byte{0x51}}

	signerKey := newResolverPrivateKey(t)

	t.Run("no psbt inputs and no tx inputs", func(t *testing.T) {
		checkpoint := &psbt.Packet{UnsignedTx: wire.NewMsgTx(2)}

		err := validateCheckpointBinding(
			arkPtx, 0, checkpoint, signerKey.PubKey(), []byte{txscript.OP_TRUE},
		)
		require.ErrorContains(t, err, "checkpoint has no inputs")
	})

	t.Run("tx inputs but no psbt inputs", func(t *testing.T) {
		checkpointTx := wire.NewMsgTx(2)
		checkpointTx.AddTxIn(&wire.TxIn{})
		checkpoint := &psbt.Packet{UnsignedTx: checkpointTx}

		err := validateCheckpointBinding(
			arkPtx, 0, checkpoint, signerKey.PubKey(), []byte{txscript.OP_TRUE},
		)
		require.ErrorContains(t, err, "checkpoint has no inputs")
	})
}

// TestRetryWithBackoffIsBounded proves the retry loop terminates on its own
// budget even when the caller supplies a context that never expires.
func TestRetryWithBackoffIsBounded(t *testing.T) {
	cfg := retryConfig{
		MinAttempts:  10,
		MaxAttempts:  4,
		MaxElapsed:   time.Second,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		Multiplier:   1,
	}

	attempts := 0
	done := make(chan error, 1)
	go func() {
		done <- retryWithBackoff(
			context.Background(),
			cfg,
			func() error { attempts++; return errAlwaysFails },
			nil,
		)
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		require.Equal(t, 4, attempts)
	case <-time.After(10 * time.Second):
		t.Fatal("retryWithBackoff did not return without a context deadline")
	}
}

var errAlwaysFails = fmt.Errorf("always fails")

func TestRetryWithBackoffExhaustsElapsedBudget(t *testing.T) {
	cfg := retryConfig{
		MaxAttempts:  0, // disabled: only the elapsed budget may fire
		MaxElapsed:   time.Millisecond,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond,
		Multiplier:   1,
		Jitter:       0, // deterministic delay
	}

	attempts := 0
	err := retryWithBackoff(
		context.Background(),
		cfg,
		func() error { attempts++; return errAlwaysFails },
		nil,
	)

	require.ErrorContains(t, err, "retry budget exhausted after attempt 1")
	require.Equal(t, 1, attempts)
}
