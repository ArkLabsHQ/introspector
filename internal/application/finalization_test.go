package application

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkintent "github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestSubmitFinalizationValidatesForfeitOutputs proves the emulator only signs
// a forfeit whose output side matches the one tree.BuildForfeitTx produces for
// the vtxo committed by the intent proof and the connector taken from the
// connector tree. Matching the vtxo input against a previously signed intent
// proof is not enough on its own: the requester supplies the whole forfeit, so
// without an output check a legitimately approved input can be spent into any
// transaction they like.
func TestSubmitFinalizationValidatesForfeitOutputs(t *testing.T) {
	fix := newForfeitFixture(t)

	attackerScript := fix.randomP2TRScript(t)

	t.Run("canonical forfeit is signed", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)

		signed, err := fix.submit(t, forfeit)
		require.NoError(t, err)
		require.Len(t, signed.Forfeits, 1)
		require.Len(t, forfeit.Inputs[0].TaprootScriptSpendSig, 1)
	})

	t.Run("whole value redirected to the requester", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		forfeit.UnsignedTx.TxOut = []*wire.TxOut{{
			Value:    fix.vtxoPrevout.Value + fix.connectorOutput.Value,
			PkScript: attackerScript,
		}}

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("value split into an extra output", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		total := fix.vtxoPrevout.Value + fix.connectorOutput.Value
		forfeit.UnsignedTx.TxOut = []*wire.TxOut{
			{Value: 1, PkScript: fix.forfeitScript},
			{Value: total - 1, PkScript: attackerScript},
			txutils.AnchorOutput(),
		}

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("anchor replaced by a requester output", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		forfeit.UnsignedTx.TxOut[1] = &wire.TxOut{Value: 0, PkScript: attackerScript}

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("forfeit output value does not conserve the inputs", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		forfeit.UnsignedTx.TxOut[0].Value -= 5_000

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("vtxo prevout inflated against the intent proof", func(t *testing.T) {
		inflated := &wire.TxOut{
			Value:    fix.vtxoPrevout.Value * 10,
			PkScript: fix.vtxoPrevout.PkScript,
		}
		forfeit := fix.buildForfeit(t, inflated, fix.connectorOutput)

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("connector prevout does not match the tree", func(t *testing.T) {
		forged := &wire.TxOut{
			Value:    fix.connectorOutput.Value * 100,
			PkScript: fix.connectorOutput.PkScript,
		}
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, forged)

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})
}

// forfeitFixture holds a signer that already approved an intent proof for a
// single vtxo, plus the connector tree that vtxo's forfeit must use.
type forfeitFixture struct {
	signerKey         *btcec.PrivateKey
	intent            Intent
	commitmentTx      *psbt.Packet
	connectorTree     *tree.TxTree
	leafScript        *psbt.TaprootTapLeafScript
	forfeitScript     []byte
	vtxoOutpoint      wire.OutPoint
	vtxoPrevout       *wire.TxOut
	connectorOutpoint wire.OutPoint
	connectorOutput   *wire.TxOut
}

func newForfeitFixture(t *testing.T) *forfeitFixture {
	t.Helper()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScript := []byte{txscript.OP_TRUE}
	scriptHash := arkade.ArkadeScriptHash(arkadeScript)

	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{
		arkade.ComputeArkadeScriptPublicKey(signerKey.PubKey(), scriptHash),
	}}
	vtxoScript := arkscript.TapscriptsVtxoScript{
		Closures: []arkscript.Closure{&closure},
	}

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	tapscript, err := closure.Script()
	require.NoError(t, err)

	tapLeaf := txscript.NewBaseTapLeaf(tapscript)
	merkleProof, err := tapTree.GetTaprootMerkleProof(tapLeaf.TapHash())
	require.NoError(t, err)

	vtxoPkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)

	fix := &forfeitFixture{
		signerKey: signerKey,
		leafScript: &psbt.TaprootTapLeafScript{
			ControlBlock: merkleProof.ControlBlock,
			Script:       merkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		},
		vtxoOutpoint: wire.OutPoint{Hash: chainhash.Hash{0xa1}, Index: 0},
		vtxoPrevout:  &wire.TxOut{Value: 100_000, PkScript: vtxoPkScript},
	}
	fix.forfeitScript = fix.randomP2TRScript(t)

	// the connector tree: a single leaf paying one connector output
	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xb1}, Index: 0},
	})
	connectorTx.AddTxOut(&wire.TxOut{Value: 450, PkScript: fix.randomP2TRScript(t)})
	connectorTx.AddTxOut(txutils.AnchorOutput())

	connectorPtx, err := psbt.NewFromUnsignedTx(connectorTx)
	require.NoError(t, err)

	fix.connectorTree = &tree.TxTree{Root: connectorPtx}
	fix.connectorOutpoint = wire.OutPoint{Hash: connectorTx.TxHash(), Index: 0}
	fix.connectorOutput = connectorTx.TxOut[0]

	fix.intent = Intent{Proof: fix.newSignedIntentProof(t, arkadeScript, tapLeaf)}

	// a commitment tx with no input the signer owns, so the boarding branch of
	// SubmitFinalization is reached but signs nothing
	commitmentTx := wire.NewMsgTx(3)
	commitmentTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xc1}, Index: 0},
	})
	commitmentTx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: fix.randomP2TRScript(t)})
	commitmentPtx, err := psbt.NewFromUnsignedTx(commitmentTx)
	require.NoError(t, err)
	commitmentPtx.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 2_000, PkScript: fix.randomP2TRScript(t),
	}
	fix.commitmentTx = commitmentPtx

	return fix
}

// newSignedIntentProof builds the intent proof the emulator signed in the past:
// input 0 is the message input, input 1 spends the vtxo and carries the
// emulator's own tapscript signature.
func (f *forfeitFixture) newSignedIntentProof(
	t *testing.T, arkadeScript []byte, tapLeaf txscript.TapLeaf,
) arkintent.Proof {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xd1}, Index: 0},
	})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: f.vtxoOutpoint})

	packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 1, Script: arkadeScript})
	require.NoError(t, err)
	packetOut, err := extension.Extension{packet}.TxOut()
	require.NoError(t, err)
	tx.AddTxOut(packetOut)

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// the message input reuses the vtxo script, see intent.New
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 0, PkScript: f.vtxoPrevout.PkScript,
	}
	ptx.Inputs[1].WitnessUtxo = f.vtxoPrevout
	ptx.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.leafScript}

	prevoutFetcher, err := computePrevoutFetcher(ptx)
	require.NoError(t, err)

	signingKey := arkade.ComputeArkadeScriptPrivateKey(
		f.signerKey, arkade.ArkadeScriptHash(arkadeScript),
	)
	message, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(tx, prevoutFetcher), txscript.SigHashDefault,
		tx, 1, prevoutFetcher, tapLeaf,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(signingKey, message)
	require.NoError(t, err)

	leafHash := tapLeaf.TapHash()
	ptx.Inputs[1].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
		LeafHash:    leafHash[:],
		Signature:   sig.Serialize(),
		SigHash:     txscript.SigHashDefault,
	}}

	return arkintent.Proof{Packet: *ptx}
}

// buildForfeit produces the forfeit tx a requester would submit, spending the
// vtxo and its connector with the prevouts it claims they have.
func (f *forfeitFixture) buildForfeit(
	t *testing.T, vtxoPrevout, connectorOutput *wire.TxOut,
) *psbt.Packet {
	t.Helper()

	forfeit, err := tree.BuildForfeitTx(
		[]*wire.OutPoint{&f.vtxoOutpoint, &f.connectorOutpoint},
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
		[]*wire.TxOut{vtxoPrevout, connectorOutput},
		f.forfeitScript,
		0,
	)
	require.NoError(t, err)

	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.leafScript}

	return forfeit
}

func (f *forfeitFixture) submit(
	t *testing.T, forfeits ...*psbt.Packet,
) (*SignedBatchFinalization, error) {
	t.Helper()

	svc := &service{signer: signer{f.signerKey}}
	return svc.SubmitFinalization(t.Context(), BatchFinalization{
		Intent:        f.intent,
		Forfeits:      forfeits,
		ConnectorTree: f.connectorTree,
		CommitmentTx:  f.commitmentTx,
	})
}

func (f *forfeitFixture) randomP2TRScript(t *testing.T) []byte {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pkScript, err := arkscript.P2TRScript(key.PubKey())
	require.NoError(t, err)
	return pkScript
}
