package covenant_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/test/covenant"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// These run the covenants through the arkade engine directly: no arkd, no
// emulator, no regtest stack. They cover everything the covenant itself decides.
// They do not cover arkd's validation (asset balance, output minimums) or the
// tapscript closures' signature and timelock requirements, both of which the
// design depends on separately.

const (
	dust      = int64(330)
	minAmount = int64(1)
)

type prevOutFetcher struct {
	txscript.PrevOutputFetcher
}

func (prevOutFetcher) FetchPrevOutArkTx(wire.OutPoint) *wire.MsgTx { return nil }

// OP_INSPECTINPUTSCRIPTPUBKEY reads this, not FetchPrevOutput. Returning nil
// here makes every covenant that inspects an input fail before reaching the
// condition under test, which turns rejection tests green for the wrong reason.
func (f prevOutFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	prev := f.FetchPrevOutput(op)
	if prev == nil {
		return nil
	}
	return prev.PkScript
}

func key(t *testing.T, seed byte) *btcec.PublicKey {
	t.Helper()
	buf := make([]byte, 32)
	buf[31] = seed
	_, pub := btcec.PrivKeyFromBytes(buf)
	return pub
}

func p2tr(t *testing.T, k *btcec.PublicKey) []byte {
	t.Helper()
	s, err := script.P2TRScript(k)
	require.NoError(t, err)
	return s
}

func subDust(t *testing.T, k *btcec.PublicKey) []byte {
	t.Helper()
	s, err := script.SubDustScript(k)
	require.NoError(t, err)
	return s
}

type spend struct {
	prevouts []*wire.TxOut
	outputs  []*wire.TxOut
	packet   asset.Packet
}

func (s spend) clone() spend {
	out := spend{
		prevouts: make([]*wire.TxOut, len(s.prevouts)),
		outputs:  make([]*wire.TxOut, len(s.outputs)),
		packet:   s.packet,
	}
	for i, p := range s.prevouts {
		cp := *p
		out.prevouts[i] = &cp
	}
	for i, o := range s.outputs {
		cp := *o
		out.outputs[i] = &cp
	}
	return out
}

// run executes the covenant as input 0 of a synthetic transaction.
func run(t *testing.T, script []byte, s spend) error {
	t.Helper()
	require.NotEmpty(t, s.prevouts)

	tx := &wire.MsgTx{Version: 2}
	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(s.prevouts))
	for i, prev := range s.prevouts {
		op := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: 0}
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: 0xfffffffd})
		prevouts[op] = prev
	}
	for _, o := range s.outputs {
		tx.AddTxOut(o)
	}

	fetcher := prevOutFetcher{txscript.NewMultiPrevOutFetcher(prevouts)}
	engine, err := arkade.NewEngine(
		script, tx, 0,
		txscript.NewSigCache(10),
		txscript.NewTxSigHashes(tx, fetcher),
		s.prevouts[0].Value,
		fetcher,
	)
	require.NoError(t, err)

	if s.packet != nil {
		engine.SetAssetPacket(s.packet)
	}
	return engine.Execute()
}

// requireRejected asserts the covenant rejected the spend by evaluating to
// false, not by failing to run. Index and stack errors mean the script aborted
// before reaching the condition under test -- a harness bug that would otherwise
// show up as a passing rejection test.
func requireRejected(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)

	var scriptErr txscript.Error
	require.ErrorAs(t, err, &scriptErr, "expected a script error, got %v", err)

	switch scriptErr.ErrorCode {
	case txscript.ErrEvalFalse, txscript.ErrVerify, txscript.ErrEqualVerify,
		txscript.ErrNumEqualVerify:
	default:
		t.Fatalf(
			"covenant aborted instead of evaluating false: %s (%v)",
			scriptErr.ErrorCode, err,
		)
	}
}

// assetID is arbitrary but must never equal the spending transaction's own hash,
// which the engine rejects as a fresh-issuance identity collision.
func assetID(index uint16) asset.AssetId {
	var txid chainhash.Hash
	for i := range txid {
		txid[i] = 0xab
	}
	return asset.AssetId{Txid: txid, Index: index}
}

// packetOf builds a single-group packet. Zero amounts are omitted, so a receiver
// holding none of the asset genuinely has no entry, which drives the miss path.
func packetOf(
	t *testing.T, id asset.AssetId, ins, outs map[uint16]uint64,
) asset.Packet {
	t.Helper()
	assetIns := make([]asset.AssetInput, 0, len(ins))
	for vin, amt := range ins {
		if amt == 0 {
			continue
		}
		in, err := asset.NewAssetInput(vin, amt)
		require.NoError(t, err)
		assetIns = append(assetIns, *in)
	}
	assetOuts := make([]asset.AssetOutput, 0, len(outs))
	for vout, amt := range outs {
		if amt == 0 {
			continue
		}
		out, err := asset.NewAssetOutput(vout, amt)
		require.NoError(t, err)
		assetOuts = append(assetOuts, *out)
	}
	grp, err := asset.NewAssetGroup(&id, nil, assetIns, assetOuts, []asset.Metadata{})
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

func params(t *testing.T, withAsset bool) covenant.Params {
	t.Helper()
	p := covenant.Params{
		ReceiverKey: key(t, 1),
		SenderKey:   key(t, 2),
		OperatorKey: key(t, 3),
		Dust:        dust,
		Topup:       dust,
		Locktime:    500_000_000,
	}
	if withAsset {
		id := assetID(0)
		p.AssetID = &id
	}
	return p
}

func TestRecycle(t *testing.T) {
	p := params(t, true)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	receiverPk := p2tr(t, p.ReceiverKey)

	// Topup == Dust, so the operator payout sits at the dust floor and pins P2TR.
	valid := func(priorUnits uint64) spend {
		return spend{
			prevouts: []*wire.TxOut{
				{Value: dust, PkScript: p2tr(t, key(t, 9))},
				{Value: dust, PkScript: receiverPk},
			},
			outputs: []*wire.TxOut{
				{Value: p.Topup, PkScript: p2tr(t, p.OperatorKey)},
				{Value: dust, PkScript: receiverPk},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 1, 1: priorUnits},
				map[uint16]uint64{1: 1 + priorUnits},
			),
		}
	}

	t.Run("receiver_holds_prior_balance", func(t *testing.T) {
		require.NoError(t, run(t, s.Recycle, valid(20)))
	})

	// The design's central claim: one script serves a receiver with no prior
	// holding, because a lookup miss returns (0, 0) and the flag is dropped.
	t.Run("receiver_holds_zero", func(t *testing.T) {
		require.NoError(t, run(t, s.Recycle, valid(0)))
	})

	t.Run("reject_wrong_receiver", func(t *testing.T) {
		c := valid(20).clone()
		c.outputs[1].PkScript = p2tr(t, key(t, 7))
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_operator_underpaid", func(t *testing.T) {
		c := valid(20).clone()
		c.outputs[0].Value--
		c.outputs[1].Value++
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_extra_input", func(t *testing.T) {
		c := valid(20).clone()
		c.prevouts = append(c.prevouts, &wire.TxOut{Value: 1000, PkScript: receiverPk})
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_wrong_account_at_input_one", func(t *testing.T) {
		c := valid(20).clone()
		c.prevouts[1].PkScript = p2tr(t, p.SenderKey)
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_asset_amount_shorted", func(t *testing.T) {
		c := valid(20).clone()
		c.packet = packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 1, 1: 20},
			map[uint16]uint64{0: 1, 1: 20},
		)
		requireRejected(t, run(t, s.Recycle, c))
	})

	// Documents a limitation, not a guarantee. A foreign AssetID misses on every
	// lookup, so the sum clause degenerates to 0 == 0 + 0 and the covenant
	// accepts. Only arkd's asset-balance validation rejects such a spend, so this
	// covenant must never be deployed against a validator that omits that check.
	t.Run("foreign_asset_id_not_caught_by_covenant_alone", func(t *testing.T) {
		c := valid(20).clone()
		c.packet = packetOf(t, assetID(7),
			map[uint16]uint64{0: 1, 1: 20},
			map[uint16]uint64{1: 21},
		)
		require.NoError(t, run(t, s.Recycle, c))
	})
}

func TestPurchase(t *testing.T) {
	p := params(t, true)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	receiverPk := p2tr(t, p.ReceiverKey)
	valid := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
		outputs:  []*wire.TxOut{{Value: dust, PkScript: receiverPk}},
		packet: packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 100}, map[uint16]uint64{0: 100},
		),
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, run(t, s.Purchase, valid))
	})

	t.Run("reject_short_value", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].Value--
		requireRejected(t, run(t, s.Purchase, c))
	})

	t.Run("reject_wrong_receiver", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].PkScript = p2tr(t, key(t, 7))
		requireRejected(t, run(t, s.Purchase, c))
	})
}

// The refund covenant is where sub-dust pinning bites: with Topup == Dust the
// operator recovers Dust-1, itself below dust, so both payouts pin OP_RETURN.
func TestRefund(t *testing.T) {
	p := params(t, true)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	topup := p.RefundTopup(minAmount)
	require.Equal(t, dust-minAmount, topup)

	valid := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
		outputs: []*wire.TxOut{
			{Value: topup, PkScript: subDust(t, p.OperatorKey)},
			{Value: dust - topup, PkScript: subDust(t, p.SenderKey)},
		},
		packet: packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
		),
	}

	t.Run("valid_subdust_pins", func(t *testing.T) {
		require.NoError(t, run(t, s.Refund, valid))
	})

	// Pinning a below-dust payout as P2TR is the silent-unspendability trap the
	// design warns about; the covenant must reject it.
	t.Run("reject_p2tr_where_subdust_required", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].PkScript = p2tr(t, p.OperatorKey)
		requireRejected(t, run(t, s.Refund, c))
	})

	t.Run("reject_sender_payload_diverted", func(t *testing.T) {
		c := valid.clone()
		c.outputs[1].PkScript = subDust(t, key(t, 7))
		requireRejected(t, run(t, s.Refund, c))
	})
}

// Bitcoin payload: no asset packet at all, and the operator's repayment is
// Dust-payload, below dust, so it pins sub-dust.
func TestBitcoinVariant(t *testing.T) {
	const payload = int64(50)

	p := params(t, false)
	p.Topup = dust - payload
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	receiverPk := p2tr(t, p.ReceiverKey)
	valid := spend{
		prevouts: []*wire.TxOut{
			{Value: dust, PkScript: p2tr(t, key(t, 9))},
			{Value: dust, PkScript: receiverPk},
		},
		outputs: []*wire.TxOut{
			{Value: p.Topup, PkScript: subDust(t, p.OperatorKey)},
			{Value: dust + payload, PkScript: receiverPk},
		},
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, run(t, s.Recycle, valid))
		require.Equal(t, payload, valid.outputs[1].Value-valid.prevouts[1].Value,
			"receiver gains exactly the payload")
		require.Equal(t, dust-payload, valid.outputs[0].Value,
			"operator is made whole")
	})

	t.Run("reject_receiver_overpaid", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].Value--
		c.outputs[1].Value++
		requireRejected(t, run(t, s.Recycle, c))
	})
}

func TestParamsValidation(t *testing.T) {
	p := params(t, false)

	t.Run("rejects_topup_above_dust", func(t *testing.T) {
		bad := p
		bad.Topup = dust + 1
		_, err := covenant.Build(bad, minAmount)
		require.Error(t, err)
	})

	t.Run("rejects_topup_below_min", func(t *testing.T) {
		bad := p
		bad.Topup = 0
		_, err := covenant.Build(bad, minAmount)
		require.Error(t, err)
	})

	// RefundTopup only differs from Topup when the operator funded the whole
	// dust unit; that single sat is the cost of an abandoned asset payment.
	t.Run("refund_topup_reserves_one_min_amount_only_when_fully_funded", func(t *testing.T) {
		full := p
		full.Topup = dust
		require.Equal(t, dust-minAmount, full.RefundTopup(minAmount))

		partial := p
		partial.Topup = dust - 50
		require.Equal(t, dust-50, partial.RefundTopup(minAmount))
	})
}
