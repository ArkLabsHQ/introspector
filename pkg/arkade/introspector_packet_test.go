package arkade

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestIntrospectorPacketSerializeDeserialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		packet IntrospectorPacket
	}{
		{
			name: "single entry",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{
						Vin:     0,
						Script:  []byte{0x01, 0x02, 0x03},
						Witness: []byte{0x04, 0x05},
					},
				},
			},
		},
		{
			name: "multiple entries",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0, Script: []byte{0x01}, Witness: []byte{0x02}},
					{Vin: 1, Script: []byte{0x03, 0x04}, Witness: []byte{0x05, 0x06}},
					{Vin: 5, Script: []byte{0x07}, Witness: []byte{}},
				},
			},
		},
		{
			name: "empty packet",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{},
			},
		},
		{
			name: "entry with empty script and witness",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0, Script: []byte{}, Witness: []byte{}},
				},
			},
		},
		{
			name: "large vin",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 65535, Script: []byte{0x01}, Witness: []byte{0x02}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Serialize()
			if err != nil {
				t.Fatalf("Serialize failed: %v", err)
			}

			got, err := DeserializeIntrospectorPacket(data)
			if err != nil {
				t.Fatalf("Deserialize failed: %v", err)
			}

			if len(got.Entries) != len(tt.packet.Entries) {
				t.Fatalf("entry count mismatch: got %d, want %d", len(got.Entries), len(tt.packet.Entries))
			}

			for i := range tt.packet.Entries {
				if got.Entries[i].Vin != tt.packet.Entries[i].Vin {
					t.Errorf("entry %d: vin mismatch: got %d, want %d", i, got.Entries[i].Vin, tt.packet.Entries[i].Vin)
				}
				if !bytes.Equal(got.Entries[i].Script, tt.packet.Entries[i].Script) {
					t.Errorf("entry %d: script mismatch", i)
				}
				if !bytes.Equal(got.Entries[i].Witness, tt.packet.Entries[i].Witness) {
					t.Errorf("entry %d: witness mismatch", i)
				}
			}
		})
	}
}

func TestIntrospectorPacketValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		packet  IntrospectorPacket
		wantErr bool
	}{
		{
			name: "valid unique vins",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0}, {Vin: 1}, {Vin: 2},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate vins",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0}, {Vin: 1}, {Vin: 0},
				},
			},
			wantErr: true,
		},
		{
			name: "empty entries valid",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.packet.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIntrospectorPacketSortByVin(t *testing.T) {
	t.Parallel()

	p := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 5}, {Vin: 0}, {Vin: 3}, {Vin: 1},
		},
	}
	p.SortByVin()

	expected := []uint16{0, 1, 3, 5}
	for i, entry := range p.Entries {
		if entry.Vin != expected[i] {
			t.Errorf("after sort, entry %d: got vin %d, want %d", i, entry.Vin, expected[i])
		}
	}
}

func TestSerializeTLVRecord(t *testing.T) {
	t.Parallel()

	p := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x01}, Witness: []byte{0x02}},
		},
	}

	record, err := p.SerializeTLVRecord()
	if err != nil {
		t.Fatalf("SerializeTLVRecord failed: %v", err)
	}

	if record[0] != IntrospectorPacketType {
		t.Errorf("TLV type byte: got 0x%02x, want 0x%02x", record[0], IntrospectorPacketType)
	}

	// Read uvarint length after type byte
	r := bytes.NewReader(record[1:])
	length, err := binary.ReadUvarint(r)
	if err != nil {
		t.Fatalf("failed to read uvarint length: %v", err)
	}

	// Remaining bytes should equal the declared length
	remaining := make([]byte, r.Len())
	r.Read(remaining)
	if uint64(len(remaining)) != length {
		t.Fatalf("length mismatch: uvarint says %d, got %d bytes", length, len(remaining))
	}

	// Deserialize the payload
	got, err := DeserializeIntrospectorPacket(remaining)
	if err != nil {
		t.Fatalf("DeserializeIntrospectorPacket failed: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Vin != 0 {
		t.Errorf("unexpected packet content after TLV roundtrip")
	}
}

func TestVarInt(t *testing.T) {
	t.Parallel()

	tests := []uint64{0, 1, 0xfc, 0xfd, 0xfe, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000}

	for _, val := range tests {
		var buf bytes.Buffer
		if err := writeVarInt(&buf, val); err != nil {
			t.Fatalf("writeVarInt(%d) failed: %v", val, err)
		}
		r := bytes.NewReader(buf.Bytes())
		got, err := readVarInt(r)
		if err != nil {
			t.Fatalf("readVarInt for %d failed: %v", val, err)
		}
		if got != val {
			t.Errorf("varint roundtrip: got %d, want %d", got, val)
		}
	}
}

func TestUvarint(t *testing.T) {
	t.Parallel()

	tests := []uint64{0, 1, 127, 128, 255, 256, 16383, 16384, 0xffffffff}

	for _, val := range tests {
		var buf bytes.Buffer
		if err := writeUvarint(&buf, val); err != nil {
			t.Fatalf("writeUvarint(%d) failed: %v", val, err)
		}
		r := bytes.NewReader(buf.Bytes())
		got, err := readUvarint(r)
		if err != nil {
			t.Fatalf("readUvarint for %d failed: %v", val, err)
		}
		if got != val {
			t.Errorf("uvarint roundtrip: got %d, want %d", got, val)
		}
	}
}

func TestStripIntrospectorPacket(t *testing.T) {
	t.Parallel()

	p := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x51}, Witness: []byte{0x01}},
		},
	}
	payload, _ := p.Serialize()

	// Build TLV: "ARK" + type 0x01 + uvarint(len(payload)) + payload
	var tlvStream bytes.Buffer
	tlvStream.Write([]byte(ArkMagic))
	tlvStream.WriteByte(IntrospectorPacketType)
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))
	tlvStream.Write(lenBuf[:n])
	tlvStream.Write(payload)
	tlvBytes := tlvStream.Bytes()

	// Build scriptPubKey: OP_RETURN + push + data
	var spk []byte
	spk = append(spk, 0x6a) // OP_RETURN
	spk = append(spk, byte(len(tlvBytes)))
	spk = append(spk, tlvBytes...)

	stripped, err := StripIntrospectorPacket(spk)
	if err != nil {
		t.Fatalf("StripIntrospectorPacket failed: %v", err)
	}

	// The stripped version should only contain OP_RETURN + "ARK" without the packet
	if len(stripped) >= len(spk) {
		t.Error("stripped scriptPubKey should be shorter than original")
	}
}

func TestDeserializeIntrospectorPacketTrailingBytes(t *testing.T) {
	t.Parallel()

	p := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x01}, Witness: []byte{0x02}},
		},
	}
	data, _ := p.Serialize()

	// Add trailing bytes
	data = append(data, 0xff, 0xff)

	_, err := DeserializeIntrospectorPacket(data)
	if err == nil {
		t.Error("expected error for trailing bytes, got nil")
	}
}

func TestParseTLVStream(t *testing.T) {
	t.Parallel()

	// Build a valid OP_RETURN with ARK magic + Introspector Packet
	p := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x51, 0x52}, Witness: []byte{0x01}},
			{Vin: 2, Script: []byte{0x53}, Witness: []byte{0x02, 0x03}},
		},
	}
	payload, err := p.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Build: "ARK" + type 0x01 + uvarint(len(payload)) + payload
	var data bytes.Buffer
	data.Write([]byte(ArkMagic))
	data.WriteByte(IntrospectorPacketType)
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))
	data.Write(lenBuf[:n])
	data.Write(payload)
	dataBytes := data.Bytes()

	// Build scriptPubKey: OP_RETURN + push + data
	var spk []byte
	spk = append(spk, 0x6a) // OP_RETURN
	spk = append(spk, byte(len(dataBytes)))
	spk = append(spk, dataBytes...)

	got, otherTLV, err := ParseTLVStream(spk)
	if err != nil {
		t.Fatalf("ParseTLVStream failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected introspector packet, got nil")
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got.Entries))
	}
	if got.Entries[0].Vin != 0 || got.Entries[1].Vin != 2 {
		t.Error("unexpected vin values")
	}
	if len(otherTLV) != 0 {
		t.Errorf("expected no other TLV data, got %d bytes", len(otherTLV))
	}
}

func TestParseTLVStreamErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spk  []byte
	}{
		{
			name: "too short",
			spk:  []byte{0x6a, 0x01},
		},
		{
			name: "not OP_RETURN",
			spk:  []byte{0x00, 0x03, 'A', 'R', 'K'},
		},
		{
			name: "wrong magic",
			spk:  []byte{0x6a, 0x03, 'F', 'O', 'O'},
		},
		{
			name: "duplicate type",
			spk: func() []byte {
				// ARK + type 0x00 + uvarint(1) + 0x00 + type 0x00 + uvarint(1) + 0x00
				var buf bytes.Buffer
				buf.Write([]byte(ArkMagic))
				buf.WriteByte(0x00)
				buf.WriteByte(0x01) // uvarint(1)
				buf.WriteByte(0x00) // data
				buf.WriteByte(0x00) // duplicate type 0x00
				buf.WriteByte(0x01) // uvarint(1)
				buf.WriteByte(0x00) // data
				data := buf.Bytes()
				var spk []byte
				spk = append(spk, 0x6a, byte(len(data)))
				spk = append(spk, data...)
				return spk
			}(),
		},
		{
			name: "truncated after type byte",
			spk: func() []byte {
				var buf bytes.Buffer
				buf.Write([]byte(ArkMagic))
				buf.WriteByte(0x00) // type byte with no length
				data := buf.Bytes()
				var spk []byte
				spk = append(spk, 0x6a, byte(len(data)))
				spk = append(spk, data...)
				return spk
			}(),
		},
		{
			name: "payload exceeds remaining data",
			spk: func() []byte {
				var buf bytes.Buffer
				buf.Write([]byte(ArkMagic))
				buf.WriteByte(0x00)
				var lenBuf [binary.MaxVarintLen64]byte
				n := binary.PutUvarint(lenBuf[:], 255) // claims 255 bytes
				buf.Write(lenBuf[:n])
				buf.WriteByte(0x00) // only 1 byte of data
				data := buf.Bytes()
				var spk []byte
				spk = append(spk, 0x6a, byte(len(data)))
				spk = append(spk, data...)
				return spk
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseTLVStream(tt.spk)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestStripIntrospectorPacketNonOpReturn(t *testing.T) {
	t.Parallel()

	// Non-OP_RETURN script should be returned as-is
	spk := []byte{0x76, 0xa9, 0x14} // OP_DUP OP_HASH160 ...
	result, err := StripIntrospectorPacket(spk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, spk) {
		t.Error("non-OP_RETURN script should be returned unchanged")
	}
}

func TestStripIntrospectorPacketNoMagic(t *testing.T) {
	t.Parallel()

	// OP_RETURN with no ARK magic
	spk := []byte{0x6a, 0x03, 0x01, 0x02, 0x03}
	result, err := StripIntrospectorPacket(spk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, spk) {
		t.Error("OP_RETURN without ARK magic should be returned unchanged")
	}
}

func TestVerifyScriptHash(t *testing.T) {
	t.Parallel()

	// Generate a test key pair
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubKey := privKey.PubKey()

	script := []byte{OP_1} // Simple script

	scriptHash, tweakedKey := VerifyScriptHash(script, pubKey)

	// Verify the script hash is 32 bytes
	if len(scriptHash) != 32 {
		t.Errorf("script hash length: got %d, want 32", len(scriptHash))
	}

	// Verify the tweaked key is different from the original
	if bytes.Equal(schnorr.SerializePubKey(tweakedKey), schnorr.SerializePubKey(pubKey)) {
		t.Error("tweaked key should differ from original public key")
	}

	// Verify consistency: same inputs produce same outputs
	scriptHash2, tweakedKey2 := VerifyScriptHash(script, pubKey)
	if !bytes.Equal(scriptHash, scriptHash2) {
		t.Error("script hash should be deterministic")
	}
	if !bytes.Equal(schnorr.SerializePubKey(tweakedKey), schnorr.SerializePubKey(tweakedKey2)) {
		t.Error("tweaked key should be deterministic")
	}

	// Different script produces different hash
	scriptHash3, _ := VerifyScriptHash([]byte{OP_2}, pubKey)
	if bytes.Equal(scriptHash, scriptHash3) {
		t.Error("different scripts should produce different hashes")
	}
}

func TestValidateCompleteness(t *testing.T) {
	t.Parallel()

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 1}},
		},
	}

	tests := []struct {
		name    string
		packet  IntrospectorPacket
		wantErr bool
	}{
		{
			name: "valid vins",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0, Script: []byte{0x51}},
					{Vin: 1, Script: []byte{0x51}},
				},
			},
			wantErr: false,
		},
		{
			name: "vin out of range",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0, Script: []byte{0x51}},
					{Vin: 5, Script: []byte{0x51}}, // Only 2 inputs
				},
			},
			wantErr: true,
		},
		{
			name: "empty entries",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.packet.ValidateCompleteness(tx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCompleteness() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateScriptHashes(t *testing.T) {
	t.Parallel()

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()

	tests := []struct {
		name    string
		packet  IntrospectorPacket
		wantErr bool
	}{
		{
			name: "valid scripts",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0, Script: []byte{OP_1}},
					{Vin: 1, Script: []byte{OP_1, OP_1, OP_EQUAL}},
				},
			},
			wantErr: false,
		},
		{
			name: "empty script",
			packet: IntrospectorPacket{
				Entries: []IntrospectorEntry{
					{Vin: 0, Script: []byte{}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.packet.ValidateScriptHashes(pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScriptHashes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyPacketIntegration(t *testing.T) {
	t.Parallel()

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()

	// A simple script: OP_1 (always succeeds, leaves true on stack)
	script := []byte{OP_1}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
		},
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {
			Value:    1000000000,
			PkScript: []byte{OP_1, OP_DATA_32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	})

	// Valid packet — script that always succeeds
	packet := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: script, Witness: []byte{}},
		},
	}

	err := VerifyPacket(packet, tx, prevoutFetcher, pubKey)
	if err != nil {
		t.Errorf("VerifyPacket failed for valid packet: %v", err)
	}

	// Invalid packet — duplicate vins
	dupPacket := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: script},
			{Vin: 0, Script: script},
		},
	}
	err = VerifyPacket(dupPacket, tx, prevoutFetcher, pubKey)
	if err == nil {
		t.Error("VerifyPacket should fail for duplicate vins")
	}

	// Invalid packet — vin out of range
	oorPacket := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 99, Script: script},
		},
	}
	err = VerifyPacket(oorPacket, tx, prevoutFetcher, pubKey)
	if err == nil {
		t.Error("VerifyPacket should fail for out-of-range vin")
	}
}

func TestBuildOpReturnScript(t *testing.T) {
	t.Parallel()

	packet := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x51}, Witness: []byte{0x01}},
		},
	}

	// Build with both assets and introspector packet
	assetsPayload := []byte{0xaa, 0xbb}
	spk, err := BuildOpReturnScript(assetsPayload, packet)
	if err != nil {
		t.Fatalf("BuildOpReturnScript failed: %v", err)
	}

	// Verify OP_RETURN
	if spk[0] != 0x6a {
		t.Errorf("expected OP_RETURN (0x6a), got 0x%02x", spk[0])
	}

	// Verify roundtrip: parse what was built
	parsed, parsedAssets, err := ParseTLVStream(spk)
	if err != nil {
		t.Fatalf("ParseTLVStream failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected introspector packet, got nil")
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0].Vin != 0 {
		t.Error("roundtrip produced unexpected packet content")
	}
	if !bytes.Equal(parsedAssets, assetsPayload) {
		t.Errorf("asset payload mismatch: got %x, want %x", parsedAssets, assetsPayload)
	}

	// Build with only introspector packet (no assets)
	spk2, err := BuildOpReturnScript(nil, packet)
	if err != nil {
		t.Fatalf("BuildOpReturnScript (no assets) failed: %v", err)
	}

	// Verify roundtrip
	parsed2, _, err := ParseTLVStream(spk2)
	if err != nil {
		t.Fatalf("ParseTLVStream failed on no-assets script: %v", err)
	}
	if parsed2 == nil {
		t.Fatal("expected introspector packet from roundtrip, got nil")
	}
	if len(parsed2.Entries) != 1 || parsed2.Entries[0].Vin != 0 {
		t.Error("roundtrip produced unexpected packet content (no assets case)")
	}
}

func TestBuildOpReturnScriptAndStrip(t *testing.T) {
	t.Parallel()

	packet := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x51}, Witness: []byte{0x01}},
			{Vin: 1, Script: []byte{0x52, 0x53}, Witness: []byte{0x02}},
		},
	}

	// Build OP_RETURN with introspector packet
	spk, err := BuildOpReturnScript(nil, packet)
	if err != nil {
		t.Fatalf("BuildOpReturnScript failed: %v", err)
	}

	// Strip the introspector packet (for sighash computation)
	stripped, err := StripIntrospectorPacket(spk)
	if err != nil {
		t.Fatalf("StripIntrospectorPacket failed: %v", err)
	}

	// The stripped version should be shorter
	if len(stripped) >= len(spk) {
		t.Errorf("stripped (%d bytes) should be shorter than original (%d bytes)",
			len(stripped), len(spk))
	}

	// Parse the stripped result — it should have an asset record but no introspector packet
	parsedStripped, _, err := ParseTLVStream(stripped)
	if err != nil {
		t.Fatalf("ParseTLVStream on stripped script failed: %v", err)
	}
	if parsedStripped != nil {
		t.Error("stripped script should not contain Introspector Packet")
	}
}
