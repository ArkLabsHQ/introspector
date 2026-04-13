package application

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

type psbtFixture struct {
	Psbt        string   `json:"psbt"`
	Checkpoints []string `json:"checkpoints"`
}

type psbtFixtureCatalog struct {
	Packets map[string]psbtFixture `json:"packets"`
}

func readPSBTFixtures(t testing.TB) map[string]psbtFixture {
	t.Helper()

	data, err := os.ReadFile("testdata/psbt_packets.json")
	require.NoError(t, err)

	var fix psbtFixtureCatalog
	require.NoError(t, json.Unmarshal(data, &fix))

	return fix.Packets
}

func psbtFixtureByName(t testing.TB, fixtures map[string]psbtFixture, name string) psbtFixture {
	t.Helper()

	fix, ok := fixtures[name]
	require.Truef(t, ok, "missing PSBT fixture %q", name)

	return fix
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
