package arkade

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)


func TestReadArkadeScript(t *testing.T) {
	fix := readScriptFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				signerPubKey := decodeXOnlyPubKey(t, f.SignerPublicKey)
				entry := decodeEntry(t, f.Entry)

				result, err := ReadArkadeScript(ptx, signerPubKey, entry)
				require.NoError(t, err)
				require.NotNil(t, result)

				require.Equal(t, entry.Script, result.script)
				require.Equal(t, ArkadeScriptHash(entry.Script), result.hash)
				require.Equal(t, len(entry.Witness), len(result.witness))
				for i := range entry.Witness {
					require.Equal(t, entry.Witness[i], result.witness[i])
				}

				expectedPubKey := ComputeArkadeScriptPublicKey(signerPubKey, result.hash)
				require.True(t, expectedPubKey.IsEqual(result.pubkey))

				tapscript := ptx.Inputs[entry.Vin].TaprootLeafScript[0].Script
				require.Equal(t, txscript.NewBaseTapLeaf(tapscript), result.tapLeaf)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				signerPubKey := decodeXOnlyPubKey(t, f.SignerPublicKey)
				entry := decodeEntry(t, f.Entry)

				_, err := ReadArkadeScript(ptx, signerPubKey, entry)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

type scriptFixtureEntry struct {
	Vin     int      `json:"vin"`
	Script  string   `json:"script"`
	Witness []string `json:"witness"`
}

type validScriptFixture struct {
	Name            string             `json:"name"`
	SignerPublicKey string             `json:"signerPublicKey"`
	Psbt            string             `json:"psbt"`
	Entry           scriptFixtureEntry `json:"entry"`
}

type invalidScriptFixture struct {
	Name            string             `json:"name"`
	SignerPublicKey string             `json:"signerPublicKey"`
	Psbt            string             `json:"psbt"`
	Entry           scriptFixtureEntry `json:"entry"`
	ErrorContains   string             `json:"errorContains"`
}

type scriptFixtures struct {
	Valid   []validScriptFixture   `json:"valid"`
	Invalid []invalidScriptFixture `json:"invalid"`
}


func readScriptFixtures(t *testing.T) scriptFixtures {
	t.Helper()
	data, err := os.ReadFile("testdata/read_arkade_script.json")
	require.NoError(t, err)

	var fix scriptFixtures
	require.NoError(t, json.Unmarshal(data, &fix))
	return fix
}

func decodePSBT(t *testing.T, b64 string) *psbt.Packet {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)
	return ptx
}

func decodeXOnlyPubKey(t *testing.T, hexStr string) *btcec.PublicKey {
	t.Helper()
	data, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	pubKey, err := schnorr.ParsePubKey(data)
	require.NoError(t, err)
	return pubKey
}

func decodeEntry(t *testing.T, raw scriptFixtureEntry) IntrospectorEntry {
	t.Helper()
	script, err := hex.DecodeString(raw.Script)
	require.NoError(t, err)

	witness := make(wire.TxWitness, len(raw.Witness))
	for i, w := range raw.Witness {
		witness[i], err = hex.DecodeString(w)
		require.NoError(t, err)
	}

	return IntrospectorEntry{
		Vin:     uint16(raw.Vin),
		Script:  script,
		Witness: witness,
	}
}
