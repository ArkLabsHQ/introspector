package arkade

import (
	"bytes"
	"testing"
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

	// Deserialize the payload (skip the type byte)
	got, err := DeserializeIntrospectorPacket(record[1:])
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

func TestStripIntrospectorPacket(t *testing.T) {
	t.Parallel()

	// Build a simple OP_RETURN with ARK magic + type 0x01 packet
	p := &IntrospectorPacket{
		Entries: []IntrospectorEntry{
			{Vin: 0, Script: []byte{0x51}, Witness: []byte{0x01}},
		},
	}
	payload, _ := p.Serialize()

	// Build TLV: type 0x01 + payload
	var tlvStream []byte
	tlvStream = append(tlvStream, []byte(ArkMagic)...)
	tlvStream = append(tlvStream, IntrospectorPacketType)
	tlvStream = append(tlvStream, payload...)

	// Build scriptPubKey: OP_RETURN + push + data
	var spk []byte
	spk = append(spk, 0x6a) // OP_RETURN
	spk = append(spk, byte(len(tlvStream)))
	spk = append(spk, tlvStream...)

	stripped, err := StripIntrospectorPacket(spk)
	if err != nil {
		t.Fatalf("StripIntrospectorPacket failed: %v", err)
	}

	// The stripped version should only contain OP_RETURN + "ARK" without the packet
	// Verify it doesn't contain the IntrospectorPacketType
	if bytes.Contains(stripped[4:], []byte{IntrospectorPacketType}) {
		t.Error("stripped scriptPubKey still contains Introspector Packet type byte")
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

	// Build: "ARK" + type 0x01 + payload
	var data []byte
	data = append(data, []byte(ArkMagic)...)
	data = append(data, IntrospectorPacketType)
	data = append(data, payload...)

	// Build scriptPubKey: OP_RETURN + push + data
	var spk []byte
	spk = append(spk, 0x6a) // OP_RETURN
	spk = append(spk, byte(len(data)))
	spk = append(spk, data...)

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
