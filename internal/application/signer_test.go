package application

import (
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestResolveArkadeScriptSigner(t *testing.T) {
	type resolveCall struct {
		entry   arkade.EmulatorEntry
		wantKey *btcec.PrivateKey
	}

	t.Run("matches exist", func(t *testing.T) {
		currentKey := newResolverPrivateKey(t)
		deprecatedKey := newResolverPrivateKey(t)
		nonMatchingDeprecatedKey := newResolverPrivateKey(t)
		matchingDeprecatedKey := newResolverPrivateKey(t)

		entry := arkade.EmulatorEntry{Vin: 0, Script: []byte{txscript.OP_TRUE}}
		mixedEntries := []arkade.EmulatorEntry{
			{Vin: 0, Script: []byte{txscript.OP_TRUE}},
			{Vin: 1, Script: []byte{txscript.OP_FALSE}},
		}

		currentPtx := newResolverPacket(t, entry, currentKey.PubKey())
		deprecatedPtx := newResolverPacket(t, entry, deprecatedKey.PubKey())
		matchingDeprecatedPtx := newResolverPacket(t, entry, matchingDeprecatedKey.PubKey())
		mixedPtx := newResolverPacketForEntries(t, []resolverEntrySigner{
			{entry: mixedEntries[0], signerPublicKey: currentKey.PubKey()},
			{entry: mixedEntries[1], signerPublicKey: deprecatedKey.PubKey()},
		})

		tests := []struct {
			name       string
			current    signer
			deprecated []signer
			ptx        *psbt.Packet
			calls      []resolveCall
		}{
			{
				name:    "matches current signer",
				current: signer{currentKey},
				ptx:     currentPtx,
				calls:   []resolveCall{{entry: entry, wantKey: currentKey}},
			},
			{
				name:       "matches deprecated signer",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        deprecatedPtx,
				calls:      []resolveCall{{entry: entry, wantKey: deprecatedKey}},
			},
			{
				name:       "prefers current signer",
				current:    signer{currentKey},
				deprecated: []signer{{currentKey}},
				ptx:        currentPtx,
				calls:      []resolveCall{{entry: entry, wantKey: currentKey}},
			},
			{
				name:       "tries deprecated signers in order",
				current:    signer{currentKey},
				deprecated: []signer{{nonMatchingDeprecatedKey}, {matchingDeprecatedKey}},
				ptx:        matchingDeprecatedPtx,
				calls:      []resolveCall{{entry: entry, wantKey: matchingDeprecatedKey}},
			},
			{
				name:       "resolves mixed key entries independently",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        mixedPtx,
				calls: []resolveCall{
					{entry: mixedEntries[0], wantKey: currentKey},
					{entry: mixedEntries[1], wantKey: deprecatedKey},
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				for _, call := range tc.calls {
					matchedSigner, script, err := resolveArkadeScriptSigner(
						tc.current, tc.deprecated, tc.ptx, call.entry,
					)

					require.NoError(t, err)
					require.Same(t, call.wantKey, matchedSigner.secretKey)
					require.NotNil(t, script)
					require.Equal(t, arkade.ArkadeScriptHash(call.entry.Script), script.Hash())
				}
			})
		}
	})

	t.Run("error", func(t *testing.T) {
		currentKey := newResolverPrivateKey(t)
		deprecatedKey := newResolverPrivateKey(t)
		packetKey := newResolverPrivateKey(t)
		entry := arkade.EmulatorEntry{Vin: 0, Script: []byte{txscript.OP_TRUE}}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		structuralPtx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		notFoundPtx := newResolverPacket(t, entry, packetKey.PubKey())

		tests := []struct {
			name       string
			current    signer
			deprecated []signer
			ptx        *psbt.Packet
			entry      arkade.EmulatorEntry
			requireErr func(t *testing.T, err error)
		}{
			{
				name:       "returns structural errors without fallback",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        structuralPtx,
				entry:      entry,
				requireErr: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "TaprootLeafScript")
				},
			},
			{
				name:       "returns not found after exhausting signers",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        notFoundPtx,
				entry:      entry,
				requireErr: func(t *testing.T, err error) {
					require.ErrorIs(t, err, arkade.ErrTweakedArkadePubKeyNotFound)
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				matchedSigner, script, err := resolveArkadeScriptSigner(
					tc.current, tc.deprecated, tc.ptx, tc.entry,
				)

				tc.requireErr(t, err)
				require.Nil(t, matchedSigner.secretKey)
				require.Nil(t, script)
			})
		}
	})
}

func newResolverPrivateKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key
}

func newResolverPacket(t *testing.T, entry arkade.EmulatorEntry, signerPublicKey *btcec.PublicKey) *psbt.Packet {
	t.Helper()

	return newResolverPacketForEntries(t, []resolverEntrySigner{
		{entry: entry, signerPublicKey: signerPublicKey},
	})
}

type resolverEntrySigner struct {
	entry           arkade.EmulatorEntry
	signerPublicKey *btcec.PublicKey
}

func newResolverPacketForEntries(t *testing.T, entries []resolverEntrySigner) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	for range entries {
		tx.AddTxIn(&wire.TxIn{})
	}

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	for _, entry := range entries {
		tweakedSigner := arkade.ComputeArkadeScriptPublicKey(
			entry.signerPublicKey, arkade.ArkadeScriptHash(entry.entry.Script),
		)
		closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedSigner}}
		tapscript, err := closure.Script()
		require.NoError(t, err)

		ptx.Inputs[entry.entry.Vin].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			Script:      tapscript,
			LeafVersion: txscript.BaseLeafVersion,
		}}
	}

	return ptx
}

func TestSignInputRejectsUnsafeSighashTypes(t *testing.T) {
	key := newResolverPrivateKey(t)
	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{
		arkade.ComputeArkadeScriptPublicKey(key.PubKey(), nil),
	}}
	tapscript, err := closure.Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(tapscript)
	tapTree := txscript.AssembleTaprootScriptTree(leaf)
	root := tapTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(key.PubKey(), root[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	prevout := &wire.TxOut{Value: 1000, PkScript: pkScript}
	prevoutFetcher := txscript.NewCannedPrevOutputFetcher(prevout.PkScript, prevout.Value)

	newPacket := func(t *testing.T, sighashType txscript.SigHashType) *psbt.Packet {
		t.Helper()

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		ptx.Inputs[0].WitnessUtxo = prevout
		ptx.Inputs[0].SighashType = sighashType
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			Script:      tapscript,
			LeafVersion: txscript.BaseLeafVersion,
		}}
		return ptx
	}

	tests := []struct {
		name        string
		sighashType txscript.SigHashType
		accepted    bool
	}{
		{name: "default", sighashType: txscript.SigHashDefault, accepted: true},
		{name: "all", sighashType: txscript.SigHashAll, accepted: true},
		{name: "none", sighashType: txscript.SigHashNone},
		{name: "single", sighashType: txscript.SigHashSingle},
		{name: "anyonecanpay", sighashType: txscript.SigHashAnyOneCanPay},
		{name: "all anyonecanpay", sighashType: txscript.SigHashAll | txscript.SigHashAnyOneCanPay},
		{name: "none anyonecanpay", sighashType: txscript.SigHashNone | txscript.SigHashAnyOneCanPay},
		{name: "single anyonecanpay", sighashType: txscript.SigHashSingle | txscript.SigHashAnyOneCanPay},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ptx := newPacket(t, tc.sighashType)

			err := signer{key}.signInput(ptx, 0, nil, prevoutFetcher)

			if tc.accepted {
				require.NoError(t, err)
				require.Len(t, ptx.Inputs[0].TaprootScriptSpendSig, 1)
				require.Equal(t, tc.sighashType, ptx.Inputs[0].TaprootScriptSpendSig[0].SigHash)
				return
			}

			require.ErrorContains(t, err, "unsupported sighash type")
			require.Empty(t, ptx.Inputs[0].TaprootScriptSpendSig)
		})
	}
}
