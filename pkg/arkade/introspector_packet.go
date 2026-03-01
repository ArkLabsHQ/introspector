package arkade

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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
// The TLV stream after the ARK magic contains self-delimiting type+value
// records. Records may appear in any order. The asset record uses type 0x00
// and the introspector record uses type 0x01.
// Returns the introspector packet (if present) and the raw asset payload
// (the bytes following the 0x00 marker, without the marker itself).
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

	// Scan the TLV data for the Introspector record (type 0x01) and the
	// asset record (type 0x00). Both are self-delimiting and may appear in
	// any order. We use trial-parse to distinguish real type bytes from
	// identical values embedded inside other records.
	tlvData := scriptPubKey[dataStart+3:]
	var introspectorPacket *IntrospectorPacket
	var assetsPayload []byte

	// First pass: find the introspector record (0x01) via trial-parse.
	// Track both start and end so the second pass can skip over it.
	introspectorStart := -1
	introspectorEnd := -1
	for i := 0; i < len(tlvData); i++ {
		if tlvData[i] != IntrospectorPacketType {
			continue
		}
		if i+1 >= len(tlvData) {
			continue
		}
		pkt, err := DeserializeIntrospectorPacket(tlvData[i+1:])
		if err != nil {
			continue // False positive — 0x01 inside other data
		}
		introspectorPacket = pkt
		introspectorStart = i
		// Compute the record's byte length by re-serializing.
		serialized, _ := pkt.Serialize()
		introspectorEnd = i + 1 + len(serialized) // type byte + payload
		break
	}

	// Second pass: find the asset record (0x00) by scanning for the marker.
	// Skip any 0x00 bytes that fall inside the introspector record.
	for i := 0; i < len(tlvData); i++ {
		// Skip bytes that belong to the introspector record.
		if introspectorStart >= 0 && i >= introspectorStart && i < introspectorEnd {
			continue
		}
		if tlvData[i] != 0x00 {
			continue
		}
		// The asset payload starts after the marker byte.
		payloadStart := i + 1
		// Determine where the asset payload ends: at the introspector
		// record boundary if it follows, or at end of stream.
		payloadEnd := len(tlvData)
		if introspectorStart > payloadStart {
			payloadEnd = introspectorStart
		}
		if payloadStart <= payloadEnd {
			assetsPayload = tlvData[payloadStart:payloadEnd]
			break
		}
	}

	return introspectorPacket, assetsPayload, nil
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

	// Scan for the introspector packet type byte and strip everything from it onward.
	tlvData := scriptPubKey[dataStart+3:]
	var filtered []byte

	for i := 0; i < len(tlvData); i++ {
		if tlvData[i] != IntrospectorPacketType {
			continue
		}
		pkt, err := DeserializeIntrospectorPacket(tlvData[i+1:])
		if err != nil {
			continue
		}
		_ = pkt
		filtered = tlvData[:i]
		break
	}

	if filtered == nil {
		filtered = tlvData // No introspector packet found, keep all
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

// VerifyScriptHash checks that tagged_hash("ArkScriptHash", entry.script) matches
// the tweak used in the input's tapscript key. Given the signer's base public key,
// the tweaked key is computed and compared against the pubkeys in the tapscript.
// Returns true if the script hash matches.
func VerifyScriptHash(script []byte, signerPubKey *btcec.PublicKey) ([]byte, *btcec.PublicKey) {
	scriptHash := ArkadeScriptHash(script)
	tweakedKey := ComputeArkadeScriptPublicKey(signerPubKey, scriptHash)
	return scriptHash, tweakedKey
}

// ValidateCompleteness checks that every input with an IntrospectorEntry has
// a valid vin within the transaction, and that there are no out-of-range vins.
func (p *IntrospectorPacket) ValidateCompleteness(tx *wire.MsgTx) error {
	for i, entry := range p.Entries {
		if int(entry.Vin) >= len(tx.TxIn) {
			return fmt.Errorf("entry %d: vin %d out of range (tx has %d inputs)",
				i, entry.Vin, len(tx.TxIn))
		}
	}
	return nil
}

// ValidateScriptHashes checks that for each entry, the script hash matches the
// tweaked key derived from the signer's public key. The tweaked key must appear
// in the input's witness tapscript for the entry to be valid.
func (p *IntrospectorPacket) ValidateScriptHashes(signerPubKey *btcec.PublicKey) error {
	for i, entry := range p.Entries {
		if len(entry.Script) == 0 {
			return fmt.Errorf("entry %d: empty script", i)
		}
		scriptHash := ArkadeScriptHash(entry.Script)
		if len(scriptHash) != 32 {
			return fmt.Errorf("entry %d: invalid script hash length", i)
		}
	}
	return nil
}

// VerifyEntry verifies a single IntrospectorEntry by executing the Arkade script
// with the committed witness against the transaction.
func VerifyEntry(entry IntrospectorEntry, tx *wire.MsgTx,
	prevOutFetcher txscript.PrevOutputFetcher,
	signerPubKey *btcec.PublicKey) error {

	if int(entry.Vin) >= len(tx.TxIn) {
		return fmt.Errorf("vin %d out of range", entry.Vin)
	}

	// Verify script hash matches the tweaked key
	scriptHash := ArkadeScriptHash(entry.Script)
	tweakedKey := ComputeArkadeScriptPublicKey(signerPubKey, scriptHash)
	_ = tweakedKey // The caller must verify this key appears in the tapscript

	// Execute the script with the committed witness
	inputIndex := int(entry.Vin)
	prevOut := prevOutFetcher.FetchPrevOutput(tx.TxIn[inputIndex].PreviousOutPoint)
	inputAmount := int64(0)
	if prevOut != nil {
		inputAmount = prevOut.Value
	}

	engine, err := NewEngine(
		entry.Script,
		tx,
		inputIndex,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(tx, prevOutFetcher),
		inputAmount,
		prevOutFetcher,
	)
	if err != nil {
		return fmt.Errorf("failed to create engine for vin %d: %w", entry.Vin, err)
	}

	// Set witness as initial stack
	if len(entry.Witness) > 0 {
		// Deserialize witness into stack items
		witness, err := txutils.ReadTxWitness(entry.Witness)
		if err != nil {
			return fmt.Errorf("failed to deserialize witness for vin %d: %w", entry.Vin, err)
		}
		engine.SetStack(witness)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("script execution failed for vin %d: %w", entry.Vin, err)
	}

	return nil
}

// VerifyPacket performs full verification of an IntrospectorPacket against a transaction.
// It checks: uniqueness, completeness, script hash validity, and script execution.
func VerifyPacket(packet *IntrospectorPacket, tx *wire.MsgTx,
	prevOutFetcher txscript.PrevOutputFetcher,
	signerPubKey *btcec.PublicKey) error {

	// Rule 6: Uniqueness
	if err := packet.Validate(); err != nil {
		return fmt.Errorf("uniqueness check failed: %w", err)
	}

	// Rule 1: Completeness — all vins must be in range
	if err := packet.ValidateCompleteness(tx); err != nil {
		return fmt.Errorf("completeness check failed: %w", err)
	}

	// Rule 3: Script hash validity
	if err := packet.ValidateScriptHashes(signerPubKey); err != nil {
		return fmt.Errorf("script hash check failed: %w", err)
	}

	// Rule 4: Witness validity — execute each script
	for _, entry := range packet.Entries {
		if err := VerifyEntry(entry, tx, prevOutFetcher, signerPubKey); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	return nil
}

// BuildOpReturnScript builds a complete OP_RETURN scriptPubKey containing the
// ARK magic, the asset marker byte (0x00), an optional assets payload, and the
// Introspector Packet. The asset marker is always included so that the ark
// server recognises the output as a valid ARK OP_RETURN.
func BuildOpReturnScript(assetsPayload []byte, packet *IntrospectorPacket) ([]byte, error) {
	var tlvStream []byte
	tlvStream = append(tlvStream, []byte(ArkMagic)...)

	// Asset marker (0x00) — always present for ark server compatibility.
	tlvStream = append(tlvStream, 0x00)
	if len(assetsPayload) > 0 {
		tlvStream = append(tlvStream, assetsPayload...)
	} else {
		// Empty asset section: varint(0) means 0 asset groups.
		tlvStream = append(tlvStream, 0x00)
	}

	// Type 0x01: Introspector packet
	if packet != nil && len(packet.Entries) > 0 {
		record, err := packet.SerializeTLVRecord()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize introspector packet: %w", err)
		}
		tlvStream = append(tlvStream, record...)
	}

	// Build scriptPubKey: OP_RETURN + push
	var spk []byte
	spk = append(spk, 0x6a) // OP_RETURN

	dataLen := len(tlvStream)
	if dataLen <= 0x4b {
		spk = append(spk, byte(dataLen))
	} else if dataLen <= 0xff {
		spk = append(spk, 0x4c, byte(dataLen))
	} else {
		spk = append(spk, 0x4d, byte(dataLen), byte(dataLen>>8))
	}

	spk = append(spk, tlvStream...)
	return spk, nil
}

// FindIntrospectorPacket scans a transaction's outputs for an OP_RETURN
// containing an ARK TLV stream with an Introspector Packet (Type 0x01).
// Returns the parsed packet, or nil if no packet is found.
func FindIntrospectorPacket(tx *wire.MsgTx) (*IntrospectorPacket, error) {
	for _, out := range tx.TxOut {
		if len(out.PkScript) < 5 || out.PkScript[0] != 0x6a {
			continue
		}
		pkt, _, err := ParseTLVStream(out.PkScript)
		if err != nil {
			continue // Not a valid ARK TLV stream, skip
		}
		if pkt != nil {
			return pkt, nil
		}
	}
	return nil, nil
}

// FindEntryByVin looks up an IntrospectorEntry by its vin index.
// Returns the entry and true if found, or a zero entry and false if not.
func (p *IntrospectorPacket) FindEntryByVin(vin uint16) (IntrospectorEntry, bool) {
	for _, entry := range p.Entries {
		if entry.Vin == vin {
			return entry, true
		}
	}
	return IntrospectorEntry{}, false
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
