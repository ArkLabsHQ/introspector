package test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// ARKD_VTXO_MIN_AMOUNT=1 in docker-compose.regtest.yml. Not exposed by GetInfo.
const dustCovenantVtxoMinAmount = int64(1)

// Genesis-era timestamp: always already satisfied, as in htlc_test.go.
const dustCovenantLocktime = arklib.AbsoluteLocktime(500_000_000)

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
	h := sha256.Sum256(subDustPkScript(t, key))
	b.AddInt64(-1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(h[:]).AddOp(arkade.OP_EQUALVERIFY)
}

func subDustPkScript(t *testing.T, key *btcec.PublicKey) []byte {
	t.Helper()
	s, err := script.SubDustScript(key)
	require.NoError(t, err)
	return s
}

// payoutPkScript is the scriptPubKey a covenant-pinned payout must actually use:
// P2TR at or above dust, sub-dust OP_RETURN below it. It must agree with
// pinOutput or the covenant rejects its own intended spend.
func payoutPkScript(t *testing.T, key *btcec.PublicKey, value, dust int64) []byte {
	t.Helper()
	if value >= dust {
		s, err := script.P2TRScript(key)
		require.NoError(t, err)
		return s
	}
	return subDustPkScript(t, key)
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

func finishCovenant(t *testing.T, b *txscript.ScriptBuilder, hasAsset bool) []byte {
	t.Helper()
	if !hasAsset {
		b.AddOp(arkade.OP_1)
	}
	s, err := b.Script()
	require.NoError(t, err)
	return s
}

// buildRecycleCovenant gates the receiver merging the covenant into an account
// they already own, repaying the operator's advance in sats.
//
//	in[0] covenant, in[1] receiver account
//	out[0] operator repaid topup, out[1] receiver's merged account
//
// Output value is enforced as a sum over both inputs rather than a constant, so
// the receiver's prior balance is irrelevant.
func buildRecycleCovenant(t *testing.T, p dustCovenantParams) []byte {
	t.Helper()
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(2).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.receiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(p.topup).AddOp(arkade.OP_EQUALVERIFY)

	pinOutput(t, b, 0, p.operatorKey, p.topup, p.dust)

	b.AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.receiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(1).AddOp(arkade.OP_INSPECTINPUTVALUE).AddOp(arkade.OP_ADD).
		AddInt64(p.topup).AddOp(arkade.OP_SUB).
		AddOp(arkade.OP_EQUALVERIFY)

	if p.assetID != nil {
		appendAssetLookup(b, 1, p.assetID, true)
		appendAssetLookup(b, 0, p.assetID, false)
		appendAssetLookup(b, 1, p.assetID, false)
		b.AddOp(arkade.OP_ADD).AddOp(arkade.OP_EQUAL)
	}
	return finishCovenant(t, b, p.assetID != nil)
}

// buildPurchaseCovenant pays the whole covenant to the receiver. The operator
// recovers nothing here, having been compensated at lockup.
func buildPurchaseCovenant(t *testing.T, p dustCovenantParams) []byte {
	t.Helper()
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.receiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).AddOp(arkade.OP_INSPECTINPUTVALUE).AddOp(arkade.OP_EQUALVERIFY)

	if p.assetID != nil {
		appendAssetLookup(b, 0, p.assetID, true)
		appendAssetLookup(b, 0, p.assetID, false)
		b.AddOp(arkade.OP_EQUAL)
	}
	return finishCovenant(t, b, p.assetID != nil)
}

// buildRefundCovenant returns the payload to the sender and repays the operator.
// Shared by the sender-signed refund leaf and the timelocked recovery leaf; the
// sender's returned payload is a sub-dust receipt, which is acceptable because
// the sender demonstrably owns a funded account and can merge it later.
func buildRefundCovenant(t *testing.T, p dustCovenantParams, vtxoMinAmount int64) []byte {
	t.Helper()
	topup := p.refundTopup(vtxoMinAmount)
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(topup).AddOp(arkade.OP_EQUALVERIFY)

	pinOutput(t, b, 0, p.operatorKey, topup, p.dust)

	b.AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(p.dust - topup).AddOp(arkade.OP_EQUALVERIFY)

	pinOutput(t, b, 1, p.senderKey, p.dust-topup, p.dust)

	if p.assetID != nil {
		appendAssetLookup(b, 1, p.assetID, true)
		appendAssetLookup(b, 0, p.assetID, false)
		b.AddOp(arkade.OP_EQUAL)
	}
	return finishCovenant(t, b, p.assetID != nil)
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

type dustCovenantContract struct {
	params   dustCovenantParams
	recycle  []byte
	purchase []byte
	refund   []byte
	vtxo     script.TapscriptsVtxoScript
	pkScript []byte
}

func newDustCovenantContract(
	t *testing.T, server, emulator, sender *btcec.PublicKey, p dustCovenantParams,
) dustCovenantContract {
	t.Helper()
	recycle := buildRecycleCovenant(t, p)
	purchase := buildPurchaseCovenant(t, p)
	refund := buildRefundCovenant(t, p, dustCovenantVtxoMinAmount)
	vtxo := buildDustCovenantVtxoScript(server, emulator, sender, p, recycle, purchase, refund)
	return dustCovenantContract{
		params:   p,
		recycle:  recycle,
		purchase: purchase,
		refund:   refund,
		vtxo:     vtxo,
		pkScript: p2trScriptForVtxoScript(t, vtxo),
	}
}

func (c dustCovenantContract) input(t *testing.T, prevTx *wire.MsgTx, leaf int) offchain.VtxoInput {
	t.Helper()
	return vtxoInputFromScriptOutput(t, prevTx, 0, c.vtxo, tapscriptAt(t, c.vtxo, leaf))
}

// issuancePacket mints a fresh asset, splitting it across the given outputs.
// Outputs with a zero amount are omitted so the recipient genuinely holds no
// entry for the asset, which is what exercises the lookup miss path.
func issuancePacket(t *testing.T, amounts map[uint16]uint64) asset.Packet {
	t.Helper()
	outs := make([]asset.AssetOutput, 0, len(amounts))
	for vout, amt := range amounts {
		if amt == 0 {
			continue
		}
		o, err := asset.NewAssetOutput(vout, amt)
		require.NoError(t, err)
		outs = append(outs, *o)
	}
	grp, err := asset.NewAssetGroup(nil, nil, []asset.AssetInput{}, outs, []asset.Metadata{})
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

// mergePacket moves the covenant's units at vin 0, plus whatever the receiver's
// account already held at vin 1, into a single output at vout 1.
func mergePacket(t *testing.T, id asset.AssetId, covenantUnits, accountUnits uint64) asset.Packet {
	t.Helper()
	in0, err := asset.NewAssetInput(0, covenantUnits)
	require.NoError(t, err)
	inputs := []asset.AssetInput{*in0}
	if accountUnits > 0 {
		in1, err := asset.NewAssetInput(1, accountUnits)
		require.NoError(t, err)
		inputs = append(inputs, *in1)
	}
	out, err := asset.NewAssetOutput(1, covenantUnits+accountUnits)
	require.NoError(t, err)
	grp, err := asset.NewAssetGroup(
		&id, nil, inputs, []asset.AssetOutput{*out}, []asset.Metadata{},
	)
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

// shortedPacket balances the group but diverts one unit away from the receiver,
// so the covenant's sum clause sees out[1] one short of in[0] + in[1].
func shortedPacket(t *testing.T, id asset.AssetId, units uint64) asset.Packet {
	t.Helper()
	require.Greater(t, units, uint64(1))
	in, err := asset.NewAssetInput(0, units)
	require.NoError(t, err)
	diverted, err := asset.NewAssetOutput(0, 1)
	require.NoError(t, err)
	out, err := asset.NewAssetOutput(1, units-1)
	require.NoError(t, err)
	grp, err := asset.NewAssetGroup(
		&id, nil, []asset.AssetInput{*in},
		[]asset.AssetOutput{*diverted, *out}, []asset.Metadata{},
	)
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

func TestDustCovenant(t *testing.T) {
	ctx := t.Context()

	sender, senderWallet, senderPubKey, grpcSender := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcSender.Close() })
	senderAddr := fundAndSettleAlice(t, ctx, sender, 100_000)

	receiver, _, receiverPubKey, grpcReceiver := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcReceiver.Close() })
	_ = fundAndSettleAlice(t, ctx, receiver, 100_000)

	_, _, operatorPubKey, grpcOperator := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcOperator.Close() })

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

	exitDelay := uint32(infos.UnilateralExitDelay)
	senderAccount := defaultVtxoScript(senderPubKey, server, exitDelay)
	receiverAccount := defaultVtxoScript(receiverPubKey, server, exitDelay)
	operatorAccount := defaultVtxoScript(operatorPubKey, server, exitDelay)

	senderAccountPk := p2trScriptForVtxoScript(t, *senderAccount)
	receiverAccountPk := p2trScriptForVtxoScript(t, *receiverAccount)

	senderKey, _, err := senderAccount.TapTree()
	require.NoError(t, err)
	receiverKey, _, err := receiverAccount.TapTree()
	require.NoError(t, err)
	operatorKey, _, err := operatorAccount.TapTree()
	require.NoError(t, err)

	baseParams := func() dustCovenantParams {
		return dustCovenantParams{
			receiverKey: receiverKey,
			senderKey:   senderKey,
			operatorKey: operatorKey,
			dust:        dust,
			topup:       dust,
			locktime:    dustCovenantLocktime,
		}
	}

	// mint issues a fresh asset into the given outputs and returns the funding
	// transaction plus its canonical AssetID. Issuance must happen in its own
	// transaction: the covenant pins the AssetID, which for an issuance derives
	// from that transaction's own txid.
	mint := func(t *testing.T, outs []*wire.TxOut, amounts map[uint16]uint64) (*wire.MsgTx, asset.AssetId) {
		t.Helper()
		tx, cps := buildWalletFundedTx(
			t, ctx, sender, indexerSvc, senderPubKey, server, exitDelay,
			outs, checkpointScript,
		)
		addAssetPacketToTx(t, tx, issuancePacket(t, amounts))
		submitWithArkd(t, ctx, tx, cps, senderWallet, grpcSender)
		h := tx.UnsignedTx.TxHash()
		return tx.UnsignedTx, asset.AssetId{Txid: [asset.TX_HASH_SIZE]byte(h), Index: 0}
	}

	// lockup spends the sender's asset-bearing account into the covenant.
	lockup := func(
		t *testing.T, mintTx *wire.MsgTx, mintVout uint32, c dustCovenantContract, units uint64,
	) *wire.MsgTx {
		t.Helper()
		in := vtxoInputFromScriptOutput(
			t, mintTx, mintVout, *senderAccount, onlyForfeitScript(t, *senderAccount),
		)
		tx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{in},
			[]*wire.TxOut{{Value: c.params.dust, PkScript: c.pkScript}},
			checkpointScript,
		)
		require.NoError(t, err)
		if c.params.assetID != nil {
			addAssetPacketToTx(t, tx, createTransferAssetPacket(
				t, mintTx.TxHash(), 0, uint16(mintVout), 0, units,
			))
		}
		submitWithArkd(t, ctx, tx, cps, senderWallet, grpcSender)
		return tx.UnsignedTx
	}

	submitToEmulator := func(t *testing.T, ptx *psbt.Packet, cps []*psbt.Packet) error {
		t.Helper()
		encoded, err := ptx.B64Encode()
		require.NoError(t, err)
		_, _, err = emulator.SubmitTx(ctx, encoded, encodeCheckpoints(t, cps))
		return err
	}

	t.Run("purchase/valid", func(t *testing.T) {
		const units = uint64(100)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{{Value: dust, PkScript: senderAccountPk}},
			map[uint16]uint64{0: units},
		)

		p := baseParams()
		p.assetID = &assetID
		c := newDustCovenantContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, units)

		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, leafPurchase)},
			[]*wire.TxOut{{Value: dust, PkScript: receiverAccountPk}},
			checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, claimTx, createTransferAssetPacket(
			t, lockTx.TxHash(), 0, 0, 0, units,
		))
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{{Vin: 0, Script: c.purchase}})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, claimTx, claimCps))
	})

	// recycleCase drives the merge path for a receiver holding priorUnits of the
	// same asset. priorUnits == 0 exercises the (0, 0) miss return of
	// OP_INSPECTINASSETLOOKUP, which is what lets one script serve both cases.
	recycleCase := func(t *testing.T, priorUnits uint64) {
		t.Helper()
		const sent = uint64(1)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{
				{Value: dust, PkScript: senderAccountPk},
				{Value: dust, PkScript: receiverAccountPk},
			},
			map[uint16]uint64{0: sent, 1: priorUnits},
		)

		p := baseParams()
		p.assetID = &assetID
		c := newDustCovenantContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, sent)

		covenantIn := c.input(t, lockTx, leafRecycle)
		accountIn := vtxoInputFromScriptOutput(
			t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
		)

		merged := covenantIn.Amount + accountIn.Amount - p.topup
		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{covenantIn, accountIn},
			[]*wire.TxOut{
				{Value: p.topup, PkScript: payoutPkScript(t, operatorKey, p.topup, dust)},
				{Value: merged, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, claimTx, mergePacket(t, assetID, sent, priorUnits))
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{{Vin: 0, Script: c.recycle}})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))

		require.Equal(t, accountIn.Amount, claimTx.UnsignedTx.TxOut[1].Value,
			"receiver's bitcoin balance must be unchanged")
		require.Equal(t, p.topup, claimTx.UnsignedTx.TxOut[0].Value,
			"operator must recover its advance in full")
	}

	t.Run("recycle/receiver_holds_prior_balance", func(t *testing.T) {
		recycleCase(t, 20)
	})

	t.Run("recycle/receiver_holds_zero", func(t *testing.T) {
		recycleCase(t, 0)
	})

	// refundCase drives the shared refund covenant. leafRefundSender additionally
	// requires the sender's signature, which the tapscript closure enforces
	// rather than the covenant, so both leaves assert the same script.
	refundCase := func(t *testing.T, leaf int) {
		t.Helper()
		const units = uint64(7)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{{Value: dust, PkScript: senderAccountPk}},
			map[uint16]uint64{0: units},
		)

		p := baseParams()
		p.assetID = &assetID
		c := newDustCovenantContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, units)
		topup := p.refundTopup(dustCovenantVtxoMinAmount)

		refundTx, refundCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, leaf)},
			[]*wire.TxOut{
				{Value: topup, PkScript: payoutPkScript(t, operatorKey, topup, dust)},
				{Value: dust - topup, PkScript: payoutPkScript(t, senderKey, dust-topup, dust)},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		refundTx.UnsignedTx.LockTime = uint32(p.locktime)
		addAssetPacketToTx(t, refundTx, createTransferAssetPacket(
			t, lockTx.TxHash(), 0, 0, 1, units,
		))
		addEmulatorPacket(t, refundTx, []arkade.EmulatorEntry{{Vin: 0, Script: c.refund}})

		require.NoError(t, executeArkadeScripts(t, refundTx, refundCps, emulatorPubKey))
		require.Equal(t, dust-topup, refundTx.UnsignedTx.TxOut[1].Value,
			"sender's returned payload must host the asset above vtxoMinAmount")
	}

	t.Run("refund/sender_signed", func(t *testing.T) {
		refundCase(t, leafRefundSender)
	})

	t.Run("recovery/after_locktime", func(t *testing.T) {
		refundCase(t, leafRecovery)
	})

	t.Run("bitcoin_variant/recycle_50_sats", func(t *testing.T) {
		const payload = int64(50)

		mintTx, _ := mint(t,
			[]*wire.TxOut{
				{Value: dust, PkScript: senderAccountPk},
				{Value: dust, PkScript: receiverAccountPk},
			},
			map[uint16]uint64{0: 1},
		)

		p := baseParams()
		p.topup = dust - payload
		c := newDustCovenantContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, 0)

		covenantIn := c.input(t, lockTx, leafRecycle)
		accountIn := vtxoInputFromScriptOutput(
			t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
		)

		merged := covenantIn.Amount + accountIn.Amount - p.topup
		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{covenantIn, accountIn},
			[]*wire.TxOut{
				{Value: p.topup, PkScript: payoutPkScript(t, operatorKey, p.topup, dust)},
				{Value: merged, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{{Vin: 0, Script: c.recycle}})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))

		require.Equal(t, payload, claimTx.UnsignedTx.TxOut[1].Value-accountIn.Amount,
			"receiver must gain exactly the payload")
		require.Equal(t, dust-payload, claimTx.UnsignedTx.TxOut[0].Value,
			"operator must be made whole")
	})

	t.Run("reject", func(t *testing.T) {
		const units = uint64(3)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{
				{Value: dust, PkScript: senderAccountPk},
				{Value: dust, PkScript: receiverAccountPk},
			},
			map[uint16]uint64{0: units},
		)

		p := baseParams()
		p.assetID = &assetID
		c := newDustCovenantContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, units)

		// buildRecycle produces a valid recycle spend, then applies a mutation.
		// Each rejection case corrupts exactly one thing.
		buildRecycle := func(
			t *testing.T, mutate func(outs []*wire.TxOut, ins *[]offchain.VtxoInput),
		) (*psbt.Packet, []*psbt.Packet) {
			t.Helper()
			covenantIn := c.input(t, lockTx, leafRecycle)
			accountIn := vtxoInputFromScriptOutput(
				t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
			)
			ins := []offchain.VtxoInput{covenantIn, accountIn}
			outs := []*wire.TxOut{
				{Value: p.topup, PkScript: payoutPkScript(t, operatorKey, p.topup, dust)},
				{
					Value:    covenantIn.Amount + accountIn.Amount - p.topup,
					PkScript: receiverAccountPk,
				},
			}
			mutate(outs, &ins)

			tx, cps, err := offchain.BuildTxs(ins, outs, checkpointScript)
			require.NoError(t, err)
			addAssetPacketToTx(t, tx, mergePacket(t, assetID, units, 0))
			addEmulatorPacket(t, tx, []arkade.EmulatorEntry{{Vin: 0, Script: c.recycle}})
			return tx, cps
		}

		expectRejected := func(t *testing.T, ptx *psbt.Packet, cps []*psbt.Packet) {
			t.Helper()
			require.Error(t, executeArkadeScripts(t, ptx, cps, emulatorPubKey))
			require.Error(t, submitToEmulator(t, ptx, cps))
		}

		t.Run("wrong_receiver", func(t *testing.T) {
			tx, cps := buildRecycle(t, func(outs []*wire.TxOut, _ *[]offchain.VtxoInput) {
				outs[1].PkScript = randomP2TRScript(t)
			})
			expectRejected(t, tx, cps)
		})

		t.Run("operator_underpaid", func(t *testing.T) {
			tx, cps := buildRecycle(t, func(outs []*wire.TxOut, _ *[]offchain.VtxoInput) {
				outs[0].Value--
				outs[1].Value++
			})
			expectRejected(t, tx, cps)
		})

		t.Run("extra_input", func(t *testing.T) {
			tx, cps := buildRecycle(t, func(_ []*wire.TxOut, ins *[]offchain.VtxoInput) {
				extra := vtxoInputFromScriptOutput(
					t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
				)
				*ins = append(*ins, extra)
			})
			expectRejected(t, tx, cps)
		})

		t.Run("wrong_account_at_input_one", func(t *testing.T) {
			tx, cps := buildRecycle(t, func(_ []*wire.TxOut, ins *[]offchain.VtxoInput) {
				(*ins)[1] = vtxoInputFromScriptOutput(
					t, mintTx, 0, *senderAccount, onlyForfeitScript(t, *senderAccount),
				)
			})
			expectRejected(t, tx, cps)
		})

		// Shorting the pinned asset is the substitution case the covenant can
		// actually catch. Swapping in a foreign AssetID instead makes all three
		// lookups miss, so the clause degenerates to 0 == 0 + 0 and passes; what
		// rejects that spend is arkd's asset-balance validation, which sees the
		// covenant's asset entering with no matching group. Substitution safety
		// is a property of the covenant and arkd together, not the covenant alone.
		t.Run("asset_amount_shorted", func(t *testing.T) {
			covenantIn := c.input(t, lockTx, leafRecycle)
			accountIn := vtxoInputFromScriptOutput(
				t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
			)
			tx, cps, err := offchain.BuildTxs(
				[]offchain.VtxoInput{covenantIn, accountIn},
				[]*wire.TxOut{
					{Value: p.topup, PkScript: payoutPkScript(t, operatorKey, p.topup, dust)},
					{
						Value:    covenantIn.Amount + accountIn.Amount - p.topup,
						PkScript: receiverAccountPk,
					},
				},
				checkpointScript,
			)
			require.NoError(t, err)
			addAssetPacketToTx(t, tx, shortedPacket(t, assetID, units))
			addEmulatorPacket(t, tx, []arkade.EmulatorEntry{{Vin: 0, Script: c.recycle}})
			expectRejected(t, tx, cps)
		})

		t.Run("recovery_before_locktime", func(t *testing.T) {
			topup := p.refundTopup(dustCovenantVtxoMinAmount)
			tx, cps, err := offchain.BuildTxs(
				[]offchain.VtxoInput{c.input(t, lockTx, leafRecovery)},
				[]*wire.TxOut{
					{Value: topup, PkScript: payoutPkScript(t, operatorKey, topup, dust)},
					{
						Value:    dust - topup,
						PkScript: payoutPkScript(t, senderKey, dust-topup, dust),
					},
				},
				checkpointScript,
			)
			require.NoError(t, err)
			tx.UnsignedTx.LockTime = uint32(p.locktime) - 1
			addAssetPacketToTx(t, tx, createTransferAssetPacket(
				t, lockTx.TxHash(), 0, 0, 1, units,
			))
			addEmulatorPacket(t, tx, []arkade.EmulatorEntry{{Vin: 0, Script: c.refund}})

			// The covenant itself does not read the locktime; the CLTV closure
			// does. Only the live emulator can reject this.
			require.Error(t, submitToEmulator(t, tx, cps))
		})
	})
}
