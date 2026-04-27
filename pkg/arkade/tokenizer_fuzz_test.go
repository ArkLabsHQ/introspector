package arkade

import (
	"bytes"
	"testing"
)

func FuzzArkadeScriptTokenizer(f *testing.F) {
	fix := readFixtures(f)

	for _, tc := range fix.Valid {
		for _, entry := range tc.Packet {
			f.Add(entry.Script)
		}
	}

	for _, tc := range fix.Invalid {
		if !tc.HasEntries {
			continue
		}

		for _, entry := range tc.Entries {
			f.Add(entry.Script)
		}
	}

	// Handcrafted edge seeds for tokenizer branches.
	f.Add([]byte{})
	f.Add([]byte{OP_FALSE})
	f.Add([]byte{OP_TRUE})

	for i := uint8(1); i <= 75; i++ {
		f.Add([]byte{i})
		f.Add([]byte{i, 0xAA})
		buf := append([]byte{i}, bytes.Repeat([]byte{0xAA}, int(i))...)
		f.Add(buf)
		buf = append([]byte{i}, bytes.Repeat([]byte{0xAA}, int(i+1))...)
		f.Add(buf)
	}

	f.Add([]byte{OP_PUSHDATA1})
	f.Add([]byte{OP_PUSHDATA1, 0x00})
	f.Add([]byte{OP_PUSHDATA1, 0x01, 0xAA})
	f.Add([]byte{OP_PUSHDATA1, 0x02, 0xAA})
	f.Add([]byte{OP_PUSHDATA2})
	f.Add([]byte{OP_PUSHDATA2, 0x01})
	f.Add([]byte{OP_PUSHDATA2, 0x00, 0x00})
	f.Add([]byte{OP_PUSHDATA2, 0x02, 0x00, 0xAA, 0xBB})
	f.Add([]byte{OP_PUSHDATA2, 0x03, 0x00, 0xAA})
	f.Add([]byte{OP_PUSHDATA4})
	f.Add([]byte{OP_PUSHDATA4, 0x01, 0x00, 0x00})
	f.Add([]byte{OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{OP_PUSHDATA4, 0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB})
	f.Add([]byte{OP_PUSHDATA4, 0x03, 0x00, 0x00, 0x00, 0xAA})
	f.Add([]byte{OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x80})

	f.Fuzz(func(t *testing.T, data []byte) {
		tokenizer := MakeScriptTokenizer(0, data)
		for tokenizer.Next() {
			_ = tokenizer.Opcode()
			_ = tokenizer.Data()
			_ = tokenizer.ByteIndex()
			_ = tokenizer.OpcodePosition()
		}
		_ = tokenizer.Script()
		_ = tokenizer.Err()
	})
}
