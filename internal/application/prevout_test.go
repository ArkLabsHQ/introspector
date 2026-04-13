package application

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

func TestArkPrevOutFetcher(t *testing.T) {
	psbtFixtures := readPSBTFixtures(t)
	fix := readPrevOutFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				packet := psbtFixtureByName(t, psbtFixtures, f.Packet)
				ptx := decodePSBT(t, packet.Psbt)
				checkpoints := decodePSBTs(t, packet.Checkpoints)

				fetcher, err := newPrevOutFetcher(ptx, checkpoints)
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
				packet := psbtFixtureByName(t, psbtFixtures, f.Packet)

				if f.DecodeErrorContains != "" {
					_, err := parsePSBT(packet.Psbt)
					require.Error(t, err)
					require.Contains(t, err.Error(), f.DecodeErrorContains)
					return
				}

				ptx := decodePSBT(t, packet.Psbt)
				checkpoints := decodePSBTs(t, packet.Checkpoints)

				_, err := newPrevOutFetcher(ptx, checkpoints)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ExpectedErr)
			})
		}
	})
}

type fixtures struct {
	Valid   []validFixture   `json:"valid"`
	Invalid []invalidFixture `json:"invalid"`
}

type validFixture struct {
	Name   string `json:"name"`
	Packet string `json:"packet"`
}

type invalidFixture struct {
	Name                string `json:"name"`
	Packet              string `json:"packet"`
	ExpectedErr         string `json:"expectedErr"`
	DecodeErrorContains string `json:"decodeErrorContains"`
}

func readPrevOutFixtures(t testing.TB) fixtures {
	t.Helper()

	data, err := os.ReadFile("testdata/ark_prevout_fetcher.json")
	require.NoError(t, err)

	var fix fixtures
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
