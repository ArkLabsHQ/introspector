package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestArkPrevOutFetcher(t *testing.T) {
	fix := readPrevOutFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				checkpoints := decodePSBTs(t, f.Checkpoints)
				require.Len(t, f.ExpectedVtxoPkScripts, len(ptx.Inputs))

				fetcher, err := newPrevOutFetcher(ptx, checkpoints)
				require.NoError(t, err)

				for inputIndex := range ptx.Inputs {
					fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevArkTxField)
					require.NoError(t, err)

					outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
					if len(fields) == 0 {
						require.Nil(t, fetcher.FetchPrevOutArkTx(outpoint))
						require.Nil(t, fetcher.FetchVtxoPrevOutPkScript(outpoint))
						continue
					}

					require.Len(t, fields, 1)

					got := fetcher.FetchPrevOutArkTx(outpoint)
					require.NotNil(t, got)
					require.Equal(t, fields[0].TxHash(), got.TxHash())

					expectedPkScriptHex := f.ExpectedVtxoPkScripts[inputIndex]
					if expectedPkScriptHex == "" {
						require.Nil(t, fetcher.FetchVtxoPrevOutPkScript(outpoint))
						continue
					}

					expectedPkScript, err := hex.DecodeString(expectedPkScriptHex)
					require.NoError(t, err)
					require.Equal(t, expectedPkScript, fetcher.FetchVtxoPrevOutPkScript(outpoint))
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				checkpoints := decodePSBTs(t, f.Checkpoints)
				_, err := newPrevOutFetcher(ptx, checkpoints)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

func TestOnchainPrevOutFetcher(t *testing.T) {
	fix := readOnchainPrevOutFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)

				fetcher, err := prevOutFetcherForOnchainTx(ptx)
				require.NoError(t, err)

				for inputIndex := range ptx.Inputs {
					fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevoutTxField)
					require.NoError(t, err)

					outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
					if len(fields) == 0 {
						require.Nil(t, fetcher.FetchPrevOutArkTx(outpoint))
						continue
					}

					require.Len(t, fields, 1)

					got := fetcher.FetchPrevOutArkTx(outpoint)
					require.NotNil(t, got)
					require.Equal(t, fields[0].TxHash(), got.TxHash())
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				_, err := prevOutFetcherForOnchainTx(ptx)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

// TestPrevOutFetcherForIntentReconcilesWitnessUtxo proves that an intent whose
// prevout tx hashes correctly to the spent outpoint can no longer assert an
// unrelated amount or script through the witness utxo the VM introspects.
func TestPrevOutFetcherForIntentReconcilesWitnessUtxo(t *testing.T) {
	honestScript := testPkScript(0xaa)
	prevTx := newFundingTx(10_000, honestScript)
	outpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	newIntent := func(t *testing.T, op wire.OutPoint, witnessUtxo *wire.TxOut) *psbt.Packet {
		t.Helper()
		ptx := newSpendingPacket(t, op, witnessUtxo)
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevArkTxField, *prevTx))
		return ptx
	}

	t.Run("inflated value is rejected", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 100_000_000, PkScript: honestScript})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "value mismatch")
	})

	t.Run("forged script is rejected", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 10_000, PkScript: testPkScript(0xbb)})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "script mismatch")
	})

	t.Run("output index out of range is rejected", func(t *testing.T) {
		op := wire.OutPoint{Hash: prevTx.TxHash(), Index: 7}
		ptx := newIntent(t, op, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "out of range")
	})

	t.Run("matching prevout is accepted", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		fetcher, err := prevOutFetcherForIntent(ptx)
		require.NoError(t, err)
		require.Equal(t, honestScript, fetcher.FetchVtxoPrevOutPkScript(outpoint))
	})

	t.Run("input without prevout tx field is still accepted", func(t *testing.T) {
		ptx := newSpendingPacket(t, outpoint, &wire.TxOut{Value: 123, PkScript: honestScript})
		_, err := prevOutFetcherForIntent(ptx)
		require.NoError(t, err)
	})
}

// TestPrevOutFetcherForOnchainTxReconcilesWitnessUtxo is the SubmitOnchainTx
// counterpart of TestPrevOutFetcherForIntentReconcilesWitnessUtxo.
func TestPrevOutFetcherForOnchainTxReconcilesWitnessUtxo(t *testing.T) {
	honestScript := testPkScript(0xaa)
	prevTx := newFundingTx(10_000, honestScript)
	outpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	newOnchain := func(t *testing.T, witnessUtxo *wire.TxOut) *psbt.Packet {
		t.Helper()
		ptx := newSpendingPacket(t, outpoint, witnessUtxo)
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx))
		return ptx
	}

	t.Run("inflated value is rejected", func(t *testing.T) {
		ptx := newOnchain(t, &wire.TxOut{Value: 100_000_000, PkScript: honestScript})
		_, err := prevOutFetcherForOnchainTx(ptx)
		require.ErrorContains(t, err, "value mismatch")
	})

	t.Run("forged script is rejected", func(t *testing.T) {
		ptx := newOnchain(t, &wire.TxOut{Value: 10_000, PkScript: testPkScript(0xbb)})
		_, err := prevOutFetcherForOnchainTx(ptx)
		require.ErrorContains(t, err, "script mismatch")
	})

	t.Run("matching prevout is accepted", func(t *testing.T) {
		ptx := newOnchain(t, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		_, err := prevOutFetcherForOnchainTx(ptx)
		require.NoError(t, err)
	})
}

// TestPrevOutFetcherForArkTxReconcilesCheckpointWitnessUtxo proves the ark tx
// flow reconciles the verified prevout tx against the checkpoint input it
// actually funds. The prevout tx carried by an ark tx input describes the
// checkpoint's input 0, not the ark input itself.
func TestPrevOutFetcherForArkTxReconcilesCheckpointWitnessUtxo(t *testing.T) {
	vtxoScript := testPkScript(0xaa)
	checkpointOutScript := testPkScript(0xcc)
	prevTx := newFundingTx(10_000, vtxoScript)
	vtxoOutpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	build := func(t *testing.T, checkpointWitnessUtxo *wire.TxOut) (*psbt.Packet, []*psbt.Packet) {
		t.Helper()

		cpTx := wire.NewMsgTx(2)
		cpTx.AddTxIn(&wire.TxIn{PreviousOutPoint: vtxoOutpoint})
		cpTx.AddTxOut(&wire.TxOut{Value: 9_500, PkScript: checkpointOutScript})

		checkpoint, err := psbt.NewFromUnsignedTx(cpTx)
		require.NoError(t, err)
		checkpoint.Inputs[0].WitnessUtxo = checkpointWitnessUtxo

		arkPtx := newSpendingPacket(
			t,
			wire.OutPoint{Hash: checkpoint.UnsignedTx.TxHash(), Index: 0},
			&wire.TxOut{Value: 9_500, PkScript: checkpointOutScript},
		)
		require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevArkTxField, *prevTx))

		return arkPtx, []*psbt.Packet{checkpoint}
	}

	t.Run("inflated checkpoint value is rejected", func(t *testing.T) {
		arkPtx, checkpoints := build(t, &wire.TxOut{Value: 100_000_000, PkScript: vtxoScript})
		_, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.ErrorContains(t, err, "value mismatch")
	})

	t.Run("forged checkpoint script is rejected", func(t *testing.T) {
		arkPtx, checkpoints := build(t, &wire.TxOut{Value: 10_000, PkScript: testPkScript(0xbb)})
		_, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.ErrorContains(t, err, "script mismatch")
	})

	t.Run("missing checkpoint witness utxo is rejected", func(t *testing.T) {
		arkPtx, checkpoints := build(t, nil)
		_, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.ErrorContains(t, err, "witness utxo")
	})

	t.Run("matching prevout is accepted", func(t *testing.T) {
		arkPtx, checkpoints := build(t, &wire.TxOut{Value: 10_000, PkScript: vtxoScript})
		fetcher, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.NoError(t, err)
		require.Equal(
			t,
			vtxoScript,
			fetcher.FetchVtxoPrevOutPkScript(arkPtx.UnsignedTx.TxIn[0].PreviousOutPoint),
		)
	})
}

type fixtures struct {
	Valid   []validFixture   `json:"valid"`
	Invalid []invalidFixture `json:"invalid"`
}

type validFixture struct {
	Name                  string   `json:"name"`
	Psbt                  string   `json:"psbt"`
	Checkpoints           []string `json:"checkpoints"`
	ExpectedVtxoPkScripts []string `json:"expectedVtxoPkScripts"`
}

type invalidFixture struct {
	Name          string   `json:"name"`
	Psbt          string   `json:"psbt"`
	Checkpoints   []string `json:"checkpoints"`
	ErrorContains string   `json:"errorContains"`
}

func readPrevOutFixtures(t testing.TB) fixtures {
	t.Helper()

	data, err := os.ReadFile("testdata/ark_prevout_fetcher.json")
	require.NoError(t, err)

	var fix fixtures
	require.NoError(t, json.Unmarshal(data, &fix))

	return fix
}

type onchainFixtures struct {
	Valid   []onchainValidFixture   `json:"valid"`
	Invalid []onchainInvalidFixture `json:"invalid"`
}

type onchainValidFixture struct {
	Name string `json:"name"`
	Psbt string `json:"psbt"`
}

type onchainInvalidFixture struct {
	Name          string `json:"name"`
	Psbt          string `json:"psbt"`
	ErrorContains string `json:"errorContains"`
}

func readOnchainPrevOutFixtures(t testing.TB) onchainFixtures {
	t.Helper()

	data, err := os.ReadFile("testdata/onchain_prevout_fetcher.json")
	require.NoError(t, err)

	var fix onchainFixtures
	require.NoError(t, json.Unmarshal(data, &fix))

	return fix
}

func newPrevOutFetcher(
	ptx *psbt.Packet, checkpoints []*psbt.Packet,
) (arkade.ArkPrevOutFetcher, error) {
	if len(checkpoints) == 0 {
		return prevOutFetcherForIntent(ptx)
	}

	return prevOutFetcherForArkTx(ptx, checkpoints)
}

func decodePSBT(t testing.TB, b64 string) *psbt.Packet {
	t.Helper()

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)

	return ptx
}

func decodePSBTs(t testing.TB, b64Packets []string) []*psbt.Packet {
	t.Helper()

	packets := make([]*psbt.Packet, 0, len(b64Packets))
	for _, b64 := range b64Packets {
		ptx := decodePSBT(t, b64)
		packets = append(packets, ptx)
	}

	return packets
}

// testPkScript builds a deterministic p2tr-looking output script.
func testPkScript(b byte) []byte {
	return append([]byte{txscript.OP_1, 0x20}, bytes.Repeat([]byte{b}, 32)...)
}

func newFundingTx(value int64, pkScript []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{9}, Index: 0}})
	tx.AddTxOut(&wire.TxOut{Value: value, PkScript: pkScript})
	return tx
}

func newSpendingPacket(t testing.TB, prevout wire.OutPoint, witnessUtxo *wire.TxOut) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevout})
	tx.AddTxOut(&wire.TxOut{Value: 500, PkScript: testPkScript(0xdd)})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = witnessUtxo

	return ptx
}
