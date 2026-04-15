package application

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

func TestArkPrevOutFetcher(t *testing.T) {
	fix := readPrevOutFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				checkpoints := decodePSBTs(t, f.Checkpoints)

				fetcher, err := newPrevOutFetcher(ptx, checkpoints)
				require.NoError(t, err)

				for inputIndex := range ptx.Inputs {
					fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevArkTxField)
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
				ptx, err := parsePSBT(f.Psbt)
				if err != nil {
					require.Error(t, err)
					require.Contains(t, err.Error(), f.ErrorContains)
					return
				}

				checkpoints, err := parsePSBTs(f.Checkpoints)
				if err != nil {
					require.Error(t, err)
					require.Contains(t, err.Error(), f.ErrorContains)
					return
				}

				_, err = newPrevOutFetcher(ptx, checkpoints)
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

				fetcher, err := prevOutFetcherForOnchainTxFromPSBT(ptx)
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
				ptx, err := parsePSBT(f.Psbt)
				if err != nil {
					require.Error(t, err)
					require.Contains(t, err.Error(), f.ErrorContains)
					return
				}

				_, err = prevOutFetcherForOnchainTxFromPSBT(ptx)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

type fixtures struct {
	Valid   []validFixture   `json:"valid"`
	Invalid []invalidFixture `json:"invalid"`
}

type validFixture struct {
	Name        string   `json:"name"`
	Psbt        string   `json:"psbt"`
	Checkpoints []string `json:"checkpoints"`
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
		return prevOutFetcherForIntentFromPSBT(ptx)
	}

	return prevOutFetcherForArkTxFromPSBT(ptx, checkpoints)
}

func decodePSBT(t testing.TB, b64 string) *psbt.Packet {
	t.Helper()

	ptx, err := parsePSBT(b64)
	require.NoError(t, err)

	return ptx
}

func decodePSBTs(t testing.TB, b64Packets []string) []*psbt.Packet {
	t.Helper()

	packets, err := parsePSBTs(b64Packets)
	require.NoError(t, err)

	return packets
}

func parsePSBT(b64 string) (*psbt.Packet, error) {
	return psbt.NewFromRawBytes(strings.NewReader(b64), true)
}

func parsePSBTs(b64Packets []string) ([]*psbt.Packet, error) {
	packets := make([]*psbt.Packet, 0, len(b64Packets))
	for _, b64 := range b64Packets {
		packet, err := parsePSBT(b64)
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}

	return packets, nil
}
