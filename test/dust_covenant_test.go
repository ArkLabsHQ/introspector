package test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// ARKD_VTXO_MIN_AMOUNT=1 in docker-compose.regtest.yml:99. Not exposed by GetInfo.
const dustCovenantVtxoMinAmount = int64(1)

const (
	leafRecycle = iota
	leafPurchase
	leafRefundSender
	leafRecovery
)

type dustCovenantParams struct {
	receiverKey *btcec.PublicKey
	senderKey   *btcec.PublicKey
	operatorKey *btcec.PublicKey
	dust        int64
	topup       int64
	assetID     *asset.AssetId
	locktime    arklib.AbsoluteLocktime
}

// refundTopup is what the operator recovers on the refund leaves. It falls below
// topup only when the operator funded the whole dust unit, where one
// vtxoMinAmount must stay behind to host the sender's returned asset.
func (p dustCovenantParams) refundTopup(vtxoMinAmount int64) int64 {
	if capped := p.dust - vtxoMinAmount; p.topup > capped {
		return capped
	}
	return p.topup
}

// pinOutput binds an output to a key. pushScriptPubKey reports a witness program
// as (program, version) but anything else as (sha256(script), -1), so a
// below-dust output must be pinned in its sub-dust OP_RETURN form.
func pinOutput(
	t *testing.T, b *txscript.ScriptBuilder, vout int64, key *btcec.PublicKey, value, dust int64,
) {
	t.Helper()
	b.AddInt64(vout).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
	if value >= dust {
		b.AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
			AddData(schnorr.SerializePubKey(key)).AddOp(arkade.OP_EQUALVERIFY)
		return
	}
	subDust, err := script.SubDustScript(key)
	require.NoError(t, err)
	h := sha256.Sum256(subDust)
	b.AddInt64(-1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(h[:]).AddOp(arkade.OP_EQUALVERIFY)
}

// appendAssetLookup leaves the asset amount on the stack, dropping the found
// flag: a miss pushes (0, 0), which is exactly "holds none of this asset".
// id.Txid must be internal byte order, never the reversed display hex.
func appendAssetLookup(b *txscript.ScriptBuilder, idx int64, id *asset.AssetId, output bool) {
	op := byte(arkade.OP_INSPECTINASSETLOOKUP)
	if output {
		op = byte(arkade.OP_INSPECTOUTASSETLOOKUP)
	}
	b.AddInt64(idx).AddData(id.Txid[:]).AddInt64(int64(id.Index)).
		AddOp(op).AddOp(arkade.OP_DROP)
}

func buildPurchaseCovenant(t *testing.T, p dustCovenantParams) []byte {
	t.Helper()
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.receiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).AddOp(arkade.OP_INSPECTINPUTVALUE).AddOp(arkade.OP_EQUALVERIFY)

	if p.assetID == nil {
		b.AddOp(arkade.OP_1)
	} else {
		appendAssetLookup(b, 0, p.assetID, true)
		appendAssetLookup(b, 0, p.assetID, false)
		b.AddOp(arkade.OP_EQUAL)
	}

	s, err := b.Script()
	require.NoError(t, err)
	return s
}

func buildDustCovenantVtxoScript(
	server, emulator, sender *btcec.PublicKey,
	p dustCovenantParams,
	recycle, purchase, refund []byte,
) script.TapscriptsVtxoScript {
	tweak := func(s []byte) *btcec.PublicKey {
		return arkade.ComputeArkadeScriptPublicKey(emulator, arkade.ArkadeScriptHash(s))
	}
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, tweak(recycle)}},
			&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, tweak(purchase)}},
			&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, sender, tweak(refund)}},
			&script.CLTVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{server, tweak(refund)},
				},
				Locktime: p.locktime,
			},
		},
	}
}

// onlyForfeitScript requires exactly one forfeit closure; this taptree has four.
func tapscriptAt(t *testing.T, vtxoScript script.TapscriptsVtxoScript, i int) []byte {
	t.Helper()
	s, err := vtxoScript.Closures[i].Script()
	require.NoError(t, err)
	return s
}

func TestDustCovenant(t *testing.T) {
	ctx := t.Context()

	sender, senderWallet, senderPubKey, grpcSender := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcSender.Close() })
	senderAddr := fundAndSettleAlice(t, ctx, sender, 100_000)

	receiver, _, receiverPubKey, grpcReceiver := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcReceiver.Close() })
	_ = fundAndSettleAlice(t, ctx, receiver, 100_000)

	operator, operatorWallet, operatorPubKey, grpcOperator := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcOperator.Close() })
	_ = fundAndSettleAlice(t, ctx, operator, 100_000)

	emulator, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() { _ = conn.Close() })

	indexerSvc := setupIndexer(t)

	infos, err := grpcSender.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScript, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	server := senderAddr.Signer
	dust := int64(infos.Dust)
	require.Greater(t, dust, dustCovenantVtxoMinAmount,
		"sub-dust outputs need ARKD_VTXO_MIN_AMOUNT below dust")

	_ = emulator
	_ = senderWallet
	_ = operatorWallet
	_ = operator
	_ = receiver
	_ = indexerSvc
	_ = checkpointScript
	_ = server
	_ = senderPubKey
	_ = receiverPubKey
	_ = operatorPubKey
	_ = emulatorPubKey

	t.Run("purchase/valid", func(t *testing.T) {
		t.Fatal("not implemented")
	})
}
