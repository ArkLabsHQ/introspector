package test

import (
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/test/covenant"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// The covenant logic itself is proven without a stack in test/covenant. This
// file checks the parts only a live arkd and emulator can: that the emulator
// signs a covenant-satisfying spend, that arkd accepts the resulting
// transaction, and that the bitcoin accounting holds end to end.

// ARKD_VTXO_MIN_AMOUNT=1 in docker-compose.regtest.yml. Not exposed by GetInfo.
const dustCovenantVtxoMinAmount = int64(1)

// Genesis-era timestamp: always already satisfied, as in htlc_test.go.
const dustCovenantLocktime = arklib.AbsoluteLocktime(500_000_000)

// onlyForfeitScript requires exactly one forfeit closure; this taptree has four.
func tapscriptAt(t *testing.T, vtxoScript script.TapscriptsVtxoScript, i int) []byte {
	t.Helper()
	s, err := vtxoScript.Closures[i].Script()
	require.NoError(t, err)
	return s
}

type dustContract struct {
	params   covenant.Params
	scripts  covenant.Scripts
	vtxo     script.TapscriptsVtxoScript
	pkScript []byte
}

func newDustContract(
	t *testing.T, server, emulator, sender *btcec.PublicKey, p covenant.Params,
) dustContract {
	t.Helper()
	scripts, err := covenant.Build(p, dustCovenantVtxoMinAmount)
	require.NoError(t, err)
	vtxo := covenant.VtxoScript(server, emulator, sender, p, scripts)
	return dustContract{
		params:   p,
		scripts:  scripts,
		vtxo:     vtxo,
		pkScript: p2trScriptForVtxoScript(t, vtxo),
	}
}

func (c dustContract) input(t *testing.T, prevTx *wire.MsgTx, leaf int) offchain.VtxoInput {
	t.Helper()
	return vtxoInputFromScriptOutput(t, prevTx, 0, c.vtxo, tapscriptAt(t, c.vtxo, leaf))
}

func (c dustContract) payout(t *testing.T, key *btcec.PublicKey, value int64) []byte {
	t.Helper()
	s, err := covenant.PayoutPkScript(key, value, c.params.Dust)
	require.NoError(t, err)
	return s
}

// issuancePacket mints a fresh asset across the given outputs. Zero amounts are
// omitted, so a recipient genuinely holds no entry for the asset.
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

	baseParams := func() covenant.Params {
		return covenant.Params{
			ReceiverKey: receiverKey,
			SenderKey:   senderKey,
			OperatorKey: operatorKey,
			Dust:        dust,
			Topup:       dust,
			Locktime:    dustCovenantLocktime,
		}
	}

	// mint issues a fresh asset into the given outputs. Issuance must happen in
	// its own transaction: the covenant pins the AssetID, which for an issuance
	// derives from that transaction's own txid, so issuing inside the lockup
	// would make the address depend on a txid that depends on the address.
	mint := func(
		t *testing.T, outs []*wire.TxOut, amounts map[uint16]uint64,
	) (*wire.MsgTx, asset.AssetId) {
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

	lockup := func(
		t *testing.T, mintTx *wire.MsgTx, mintVout uint32, c dustContract, units uint64,
	) *wire.MsgTx {
		t.Helper()
		in := vtxoInputFromScriptOutput(
			t, mintTx, mintVout, *senderAccount, onlyForfeitScript(t, *senderAccount),
		)
		tx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{in},
			[]*wire.TxOut{{Value: c.params.Dust, PkScript: c.pkScript}},
			checkpointScript,
		)
		require.NoError(t, err)
		if c.params.AssetID != nil {
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

	t.Run("purchase", func(t *testing.T) {
		const units = uint64(100)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{{Value: dust, PkScript: senderAccountPk}},
			map[uint16]uint64{0: units},
		)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, units)

		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafPurchase)},
			[]*wire.TxOut{{Value: dust, PkScript: receiverAccountPk}},
			checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, claimTx, createTransferAssetPacket(
			t, lockTx.TxHash(), 0, 0, 0, units,
		))
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Purchase},
		})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, claimTx, claimCps))
	})

	// recycleCase drives the merge path for a receiver holding priorUnits of the
	// same asset. priorUnits == 0 exercises the lookup miss path.
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
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, sent)

		covenantIn := c.input(t, lockTx, covenant.LeafRecycle)
		accountIn := vtxoInputFromScriptOutput(
			t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
		)

		merged := covenantIn.Amount + accountIn.Amount - p.Topup
		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{covenantIn, accountIn},
			[]*wire.TxOut{
				{Value: p.Topup, PkScript: c.payout(t, operatorKey, p.Topup)},
				{Value: merged, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, claimTx, mergePacket(t, assetID, sent, priorUnits))
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Recycle},
		})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, claimTx, claimCps))

		require.Equal(t, accountIn.Amount, claimTx.UnsignedTx.TxOut[1].Value,
			"receiver's bitcoin balance must be unchanged")
		require.Equal(t, p.Topup, claimTx.UnsignedTx.TxOut[0].Value,
			"operator must recover its advance in full")
	}

	t.Run("recycle/receiver_holds_prior_balance", func(t *testing.T) {
		recycleCase(t, 20)
	})

	t.Run("recycle/receiver_holds_zero", func(t *testing.T) {
		recycleCase(t, 0)
	})

	t.Run("recovery/after_locktime", func(t *testing.T) {
		const units = uint64(7)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{{Value: dust, PkScript: senderAccountPk}},
			map[uint16]uint64{0: units},
		)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, units)
		topup := p.RefundTopup(dustCovenantVtxoMinAmount)

		refundTx, refundCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafRecovery)},
			[]*wire.TxOut{
				{Value: topup, PkScript: c.payout(t, operatorKey, topup)},
				{Value: dust - topup, PkScript: c.payout(t, senderKey, dust-topup)},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		refundTx.UnsignedTx.LockTime = uint32(p.Locktime)
		addAssetPacketToTx(t, refundTx, createTransferAssetPacket(
			t, lockTx.TxHash(), 0, 0, 1, units,
		))
		addEmulatorPacket(t, refundTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Refund},
		})

		require.NoError(t, executeArkadeScripts(t, refundTx, refundCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, refundTx, refundCps))
	})

	// The covenant does not read the locktime; the CLTV closure does. Only a live
	// emulator can reject this, which is why it has no counterpart in the
	// stack-free covenant tests.
	t.Run("recovery/rejected_before_locktime", func(t *testing.T) {
		const units = uint64(7)

		mintTx, assetID := mint(t,
			[]*wire.TxOut{{Value: dust, PkScript: senderAccountPk}},
			map[uint16]uint64{0: units},
		)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, units)
		topup := p.RefundTopup(dustCovenantVtxoMinAmount)

		tx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafRecovery)},
			[]*wire.TxOut{
				{Value: topup, PkScript: c.payout(t, operatorKey, topup)},
				{Value: dust - topup, PkScript: c.payout(t, senderKey, dust-topup)},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		tx.UnsignedTx.LockTime = uint32(p.Locktime) - 1
		addAssetPacketToTx(t, tx, createTransferAssetPacket(
			t, lockTx.TxHash(), 0, 0, 1, units,
		))
		addEmulatorPacket(t, tx, []arkade.EmulatorEntry{{Vin: 0, Script: c.scripts.Refund}})

		require.Error(t, submitToEmulator(t, tx, cps))
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
		p.Topup = dust - payload
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, 0, c, 0)

		covenantIn := c.input(t, lockTx, covenant.LeafRecycle)
		accountIn := vtxoInputFromScriptOutput(
			t, mintTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
		)

		merged := covenantIn.Amount + accountIn.Amount - p.Topup
		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{covenantIn, accountIn},
			[]*wire.TxOut{
				{Value: p.Topup, PkScript: c.payout(t, operatorKey, p.Topup)},
				{Value: merged, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Recycle},
		})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, claimTx, claimCps))

		require.Equal(t, payload, claimTx.UnsignedTx.TxOut[1].Value-accountIn.Amount,
			"receiver must gain exactly the payload")
		require.Equal(t, dust-payload, claimTx.UnsignedTx.TxOut[0].Value,
			"operator must be made whole")
	})
}
