package arkade

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

const (
	// IntrospectorPacketType is the TLV type for the Introspector Packet.
	IntrospectorPacketType = 0x01

	// ArkMagic is the magic bytes prefix for the ARK TLV stream.
	ArkMagic = "ARK"
)

// IntrospectorEntry represents a single entry in the Introspector Packet.
type IntrospectorEntry struct {
	Vin     uint16 // Transaction input index (u16 LE)
	Script  []byte // Arkade Script bytecode
	Witness []byte // Script witness data
}

// IntrospectorPacket represents the complete Introspector Packet.
type IntrospectorPacket struct {
	Entries []IntrospectorEntry
}

// Serialize serializes the IntrospectorPacket to bytes.
func (p *IntrospectorPacket) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Write entry count as varint
	if err := writeVarInt(&buf, uint64(len(p.Entries))); err != nil {
		return nil, fmt.Errorf("failed to write entry count: %w", err)
	}

	for i, entry := range p.Entries {
		// Write vin as u16 LE
		if err := binary.Write(&buf, binary.LittleEndian, entry.Vin); err != nil {
			return nil, fmt.Errorf("failed to write vin for entry %d: %w", i, err)
		}

		// Write script_len + script
		if err := writeVarInt(&buf, uint64(len(entry.Script))); err != nil {
			return nil, fmt.Errorf("failed to write script_len for entry %d: %w", i, err)
		}
		if _, err := buf.Write(entry.Script); err != nil {
			return nil, fmt.Errorf("failed to write script for entry %d: %w", i, err)
		}

		// Write witness_len + witness
		if err := writeVarInt(&buf, uint64(len(entry.Witness))); err != nil {
			return nil, fmt.Errorf("failed to write witness_len for entry %d: %w", i, err)
		}
		if _, err := buf.Write(entry.Witness); err != nil {
			return nil, fmt.Errorf("failed to write witness for entry %d: %w", i, err)
		}
	}

	return buf.Bytes(), nil
}

// DeserializeIntrospectorPacket deserializes an IntrospectorPacket from bytes.
func DeserializeIntrospectorPacket(data []byte) (*IntrospectorPacket, error) {
	r := bytes.NewReader(data)

	entryCount, err := readVarInt(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read entry count: %w", err)
	}

	entries := make([]IntrospectorEntry, 0, entryCount)
	for i := uint64(0); i < entryCount; i++ {
		var entry IntrospectorEntry

		// Read vin (u16 LE)
		if err := binary.Read(r, binary.LittleEndian, &entry.Vin); err != nil {
			return nil, fmt.Errorf("failed to read vin for entry %d: %w", i, err)
		}

		// Read script
		scriptLen, err := readVarInt(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read script_len for entry %d: %w", i, err)
		}
		entry.Script = make([]byte, scriptLen)
		if _, err := io.ReadFull(r, entry.Script); err != nil {
			return nil, fmt.Errorf("failed to read script for entry %d: %w", i, err)
		}

		// Read witness
		witnessLen, err := readVarInt(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read witness_len for entry %d: %w", i, err)
		}
		entry.Witness = make([]byte, witnessLen)
		if _, err := io.ReadFull(r, entry.Witness); err != nil {
			return nil, fmt.Errorf("failed to read witness for entry %d: %w", i, err)
		}

		entries = append(entries, entry)
	}

	if r.Len() != 0 {
		return nil, fmt.Errorf("unexpected %d trailing bytes", r.Len())
	}

	return &IntrospectorPacket{Entries: entries}, nil
}

// Validate checks the IntrospectorPacket for structural validity.
func (p *IntrospectorPacket) Validate() error {
	seen := make(map[uint16]bool)
	for i, entry := range p.Entries {
		if seen[entry.Vin] {
			return fmt.Errorf("duplicate vin %d at entry %d", entry.Vin, i)
		}
		seen[entry.Vin] = true
	}
	return nil
}

// SortByVin sorts entries by vin in ascending order.
func (p *IntrospectorPacket) SortByVin() {
	sort.Slice(p.Entries, func(i, j int) bool {
		return p.Entries[i].Vin < p.Entries[j].Vin
	})
}

// SerializeTLVRecord serializes the packet as a complete TLV record
// (type byte + payload).
func (p *IntrospectorPacket) SerializeTLVRecord() ([]byte, error) {
	payload, err := p.Serialize()
	if err != nil {
		return nil, err
	}
	return append([]byte{IntrospectorPacketType}, payload...), nil
}

// ParseTLVStream parses an ARK TLV stream from an OP_RETURN scriptPubKey,
// extracting any Introspector Packet found.
// Returns the introspector packet (if present) and the remaining TLV data.
func ParseTLVStream(scriptPubKey []byte) (*IntrospectorPacket, []byte, error) {
	// OP_RETURN (0x6a) + push data + "ARK" magic + TLV records
	// Minimum: OP_RETURN + push + "ARK" = at least 5 bytes
	if len(scriptPubKey) < 5 {
		return nil, nil, fmt.Errorf("scriptPubKey too short")
	}
	if scriptPubKey[0] != 0x6a { // OP_RETURN
		return nil, nil, fmt.Errorf("not an OP_RETURN output")
	}

	// Find ARK magic in the data after OP_RETURN
	// The push opcode follows OP_RETURN, then "ARK" magic
	pushStart := 1
	var dataStart int
	pushByte := scriptPubKey[pushStart]

	if pushByte <= 0x4b { // Direct push (1-75 bytes)
		dataStart = pushStart + 1
	} else if pushByte == 0x4c { // OP_PUSHDATA1
		dataStart = pushStart + 2
	} else if pushByte == 0x4d { // OP_PUSHDATA2
		dataStart = pushStart + 3
	} else {
		return nil, nil, fmt.Errorf("unexpected push opcode: 0x%02x", pushByte)
	}

	if dataStart+3 > len(scriptPubKey) {
		return nil, nil, fmt.Errorf("not enough data for ARK magic")
	}

	magic := scriptPubKey[dataStart : dataStart+3]
	if string(magic) != ArkMagic {
		return nil, nil, fmt.Errorf("ARK magic not found, got %x", magic)
	}

	// Parse TLV records after magic
	tlvData := scriptPubKey[dataStart+3:]
	var introspectorPacket *IntrospectorPacket
	var otherTLV []byte

	offset := 0
	for offset < len(tlvData) {
		tlvType := tlvData[offset]
		offset++

		if tlvType == IntrospectorPacketType {
			// Self-delimiting: parse the packet from remaining data
			pkt, err := DeserializeIntrospectorPacket(tlvData[offset:])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse introspector packet: %w", err)
			}
			introspectorPacket = pkt
			// Since it's self-delimiting, we consumed all remaining data
			break
		} else {
			// For other TLV types, we'd need their specific parsing
			// For now, treat remaining data as other TLV
			otherTLV = append(otherTLV, tlvType)
			otherTLV = append(otherTLV, tlvData[offset:]...)
			break
		}
	}

	return introspectorPacket, otherTLV, nil
}

// StripIntrospectorPacket returns the scriptPubKey with the Introspector Packet
// TLV record (Type 0x01) removed. Used for sighash computation.
func StripIntrospectorPacket(scriptPubKey []byte) ([]byte, error) {
	if len(scriptPubKey) < 5 || scriptPubKey[0] != 0x6a {
		return scriptPubKey, nil // Not an OP_RETURN, return as-is
	}

	// Find data area
	pushStart := 1
	var dataStart int
	pushByte := scriptPubKey[pushStart]

	if pushByte <= 0x4b {
		dataStart = pushStart + 1
	} else if pushByte == 0x4c {
		dataStart = pushStart + 2
	} else if pushByte == 0x4d {
		dataStart = pushStart + 3
	} else {
		return scriptPubKey, nil
	}

	if dataStart+3 > len(scriptPubKey) || string(scriptPubKey[dataStart:dataStart+3]) != ArkMagic {
		return scriptPubKey, nil // No ARK magic
	}

	// Parse TLV records, rebuilding without type 0x01
	tlvData := scriptPubKey[dataStart+3:]
	var filtered []byte

	offset := 0
	for offset < len(tlvData) {
		tlvType := tlvData[offset]

		if tlvType == IntrospectorPacketType {
			// Skip the introspector packet (self-delimiting, consumes rest)
			break
		}

		// Include this TLV record
		// For type 0x00 (Assets), it's also self-delimiting
		filtered = append(filtered, tlvData[offset:]...)
		break
	}

	// Rebuild scriptPubKey
	newData := append([]byte(ArkMagic), filtered...)

	// Build new scriptPubKey with OP_RETURN + push
	var result []byte
	result = append(result, 0x6a) // OP_RETURN

	dataLen := len(newData)
	if dataLen <= 0x4b {
		result = append(result, byte(dataLen))
	} else if dataLen <= 0xff {
		result = append(result, 0x4c, byte(dataLen))
	} else {
		result = append(result, 0x4d, byte(dataLen), byte(dataLen>>8))
	}

	result = append(result, newData...)
	return result, nil
}

// writeVarInt writes a Bitcoin-style variable-length integer.
func writeVarInt(buf *bytes.Buffer, v uint64) error {
	switch {
	case v < 0xfd:
		return buf.WriteByte(byte(v))
	case v <= 0xffff:
		if err := buf.WriteByte(0xfd); err != nil {
			return err
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(v))
		_, err := buf.Write(b)
		return err
	case v <= 0xffffffff:
		if err := buf.WriteByte(0xfe); err != nil {
			return err
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v))
		_, err := buf.Write(b)
		return err
	default:
		if err := buf.WriteByte(0xff); err != nil {
			return err
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		_, err := buf.Write(b)
		return err
	}
}

// readVarInt reads a Bitcoin-style variable-length integer.
func readVarInt(r *bytes.Reader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch {
	case b < 0xfd:
		return uint64(b), nil
	case b == 0xfd:
		buf := make([]byte, 2)
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint16(buf)), nil
	case b == 0xfe:
		buf := make([]byte, 4)
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint32(buf)), nil
	default:
		buf := make([]byte, 8)
		if _, err := r.Read(buf); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(buf), nil
	}
}
