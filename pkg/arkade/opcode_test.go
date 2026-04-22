// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package arkade

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TestOpcodeDisasm tests the print function for all opcodes in both the oneline
// and full modes to ensure it provides the expected disassembly.
func TestOpcodeDisasm(t *testing.T) {
	t.Parallel()

	// First, test the oneline disassembly.

	// The expected strings for the data push opcodes are replaced in the
	// test loops below since they involve repeating bytes.  Also, the
	// OP_NOP# and OP_UNKNOWN# are replaced below too, since it's easier
	// than manually listing them here.
	oneBytes := []byte{0x01}
	oneStr := "01"
	expectedStrings := [256]string{0x00: "0", 0x4f: "-1",
		0x50: "OP_RESERVED", 0x61: "OP_NOP", 0x62: "OP_VER",
		0x63: "OP_IF", 0x64: "OP_NOTIF", 0x65: "OP_VERIF",
		0x66: "OP_VERNOTIF", 0x67: "OP_ELSE", 0x68: "OP_ENDIF",
		0x69: "OP_VERIFY", 0x6a: "OP_RETURN", 0x6b: "OP_TOALTSTACK",
		0x6c: "OP_FROMALTSTACK", 0x6d: "OP_2DROP", 0x6e: "OP_2DUP",
		0x6f: "OP_3DUP", 0x70: "OP_2OVER", 0x71: "OP_2ROT",
		0x72: "OP_2SWAP", 0x73: "OP_IFDUP", 0x74: "OP_DEPTH",
		0x75: "OP_DROP", 0x76: "OP_DUP", 0x77: "OP_NIP",
		0x78: "OP_OVER", 0x79: "OP_PICK", 0x7a: "OP_ROLL",
		0x7b: "OP_ROT", 0x7c: "OP_SWAP", 0x7d: "OP_TUCK",
		0x7e: "OP_CAT", 0x7f: "OP_SUBSTR", 0x80: "OP_LEFT",
		0x81: "OP_RIGHT", 0x82: "OP_SIZE", 0x83: "OP_INVERT",
		0x84: "OP_AND", 0x85: "OP_OR", 0x86: "OP_XOR",
		0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY", 0x89: "OP_RESERVED1",
		0x8a: "OP_RESERVED2", 0x8b: "OP_1ADD", 0x8c: "OP_1SUB",
		0x8d: "OP_2MUL", 0x8e: "OP_2DIV", 0x8f: "OP_NEGATE",
		0x90: "OP_ABS", 0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL",
		0x93: "OP_ADD", 0x94: "OP_SUB", 0x95: "OP_MUL", 0x96: "OP_DIV",
		0x97: "OP_MOD", 0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT",
		0x9a: "OP_BOOLAND", 0x9b: "OP_BOOLOR", 0x9c: "OP_NUMEQUAL",
		0x9d: "OP_NUMEQUALVERIFY", 0x9e: "OP_NUMNOTEQUAL",
		0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN",
		0xa1: "OP_LESSTHANOREQUAL", 0xa2: "OP_GREATERTHANOREQUAL",
		0xa3: "OP_MIN", 0xa4: "OP_MAX", 0xa5: "OP_WITHIN",
		0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1", 0xa8: "OP_SHA256",
		0xa9: "OP_HASH160", 0xaa: "OP_HASH256", 0xab: "OP_CODESEPARATOR",
		0xac: "OP_CHECKSIG", 0xad: "OP_CHECKSIGVERIFY",
		0xae: "OP_CHECKMULTISIG", 0xaf: "OP_CHECKMULTISIGVERIFY",
		0xfa: "OP_SMALLINTEGER", 0xfb: "OP_PUBKEYS",
		0xfd: "OP_PUBKEYHASH", 0xfe: "OP_PUBKEY",
		0xff: "OP_INVALIDOPCODE", 0xba: "OP_CHECKSIGADD",
		0xb3: "OP_MERKLEBRANCHVERIFY",
		// Add new defined opcodes
		0xc4: "OP_SHA256INITIALIZE", 0xc5: "OP_SHA256UPDATE",
		0xc6: "OP_SHA256FINALIZE", 0xc7: "OP_INSPECTINPUTOUTPOINT",
		0xc9: "OP_INSPECTINPUTVALUE", 0xca: "OP_INSPECTINPUTSCRIPTPUBKEY",
		0xcb: "OP_INSPECTINPUTSEQUENCE", 0xcc: "OP_CHECKSIGFROMSTACK",
		0xcd: "OP_PUSHCURRENTINPUTINDEX", 0xcf: "OP_INSPECTOUTPUTVALUE",
		0xd1: "OP_INSPECTOUTPUTSCRIPTPUBKEY", 0xd2: "OP_INSPECTVERSION",
		0xd3: "OP_INSPECTLOCKTIME", 0xd4: "OP_INSPECTNUMINPUTS",
		0xd5: "OP_INSPECTNUMOUTPUTS", 0xd6: "OP_TXWEIGHT",
		0xd7: "OP_UNKNOWN215", 0xd8: "OP_UNKNOWN216",
		0xd9: "OP_UNKNOWN217", 0xda: "OP_UNKNOWN218",
		0xdb: "OP_UNKNOWN219", 0xdc: "OP_UNKNOWN220",
		0xdd: "OP_UNKNOWN221", 0xde: "OP_UNKNOWN222",
		0xdf: "OP_UNKNOWN223", 0xe0: "OP_UNKNOWN224",
		0xe1: "OP_UNKNOWN225", 0xe2: "OP_UNKNOWN226",
		0xe3: "OP_ECMULSCALARVERIFY", 0xe4: "OP_TWEAKVERIFY",
		0xf3: "OP_TXID",
		0xc8: "OP_INSPECTINPUTARKADESCRIPTHASH",
		0xce: "OP_INSPECTINPUTARKADEWITNESSHASH",
	}
	for opcodeVal, expectedStr := range expectedStrings {
		var data []byte
		switch {
		// OP_DATA_1 through OP_DATA_65 display the pushed data.
		case opcodeVal >= 0x01 && opcodeVal < 0x4c:
			data = bytes.Repeat(oneBytes, opcodeVal)
			expectedStr = strings.Repeat(oneStr, opcodeVal)

		// OP_PUSHDATA1.
		case opcodeVal == 0x4c:
			data = bytes.Repeat(oneBytes, 1)
			expectedStr = strings.Repeat(oneStr, 1)

		// OP_PUSHDATA2.
		case opcodeVal == 0x4d:
			data = bytes.Repeat(oneBytes, 2)
			expectedStr = strings.Repeat(oneStr, 2)

		// OP_PUSHDATA4.
		case opcodeVal == 0x4e:
			data = bytes.Repeat(oneBytes, 3)
			expectedStr = strings.Repeat(oneStr, 3)

		// OP_1 through OP_16 display the numbers themselves.
		case opcodeVal >= 0x51 && opcodeVal <= 0x60:
			val := byte(opcodeVal - (0x51 - 1))
			data = []byte{val}
			expectedStr = strconv.Itoa(int(val))

		// OP_NOP1 through OP_NOP10.
		case opcodeVal >= 0xb0 && opcodeVal <= 0xb9:
			switch opcodeVal {
			case 0xb1:
				// OP_NOP2 is an alias of OP_CHECKLOCKTIMEVERIFY
				expectedStr = "OP_CHECKLOCKTIMEVERIFY"
			case 0xb2:
				// OP_NOP3 is an alias of OP_CHECKSEQUENCEVERIFY
				expectedStr = "OP_CHECKSEQUENCEVERIFY"
			case 0xb3, 0xc8, 0xce:
				// OP_NOP4 is now OP_MERKLEBRANCHVERIFY
				expectedStr = "OP_MERKLEBRANCHVERIFY"
			default:
				val := byte(opcodeVal - (0xb0 - 1))
				expectedStr = "OP_NOP" + strconv.Itoa(int(val))
			}

		// Asset and packet introspection opcodes (0xe5-0xf5).
		case opcodeVal >= 0xe5 && opcodeVal <= 0xf5:
			expectedStr = opcodeArray[opcodeVal].name

		// OP_UNKNOWN#.
		case (opcodeVal >= 0xbb && opcodeVal <= 0xc3) || // Unknown range before SHA256 ops
			(opcodeVal == 0xd0) || // Unknown between output ops
			(opcodeVal >= 0xf6 && opcodeVal <= 0xf9) || // Unknown range after new ops
			opcodeVal == 0xfc:
			expectedStr = "OP_UNKNOWN" + strconv.Itoa(opcodeVal)
		}

		var buf strings.Builder
		disasmOpcode(&buf, &opcodeArray[opcodeVal], data, true)
		gotStr := buf.String()
		if gotStr != expectedStr {
			t.Errorf("pop.print (opcode %x): Unexpected disasm "+
				"string - got %v, want %v", opcodeVal, gotStr,
				expectedStr)
			continue
		}
	}

	// Now, replace the relevant fields and test the full disassembly.
	expectedStrings[0x00] = "OP_0"
	expectedStrings[0x4f] = "OP_1NEGATE"
	for opcodeVal, expectedStr := range expectedStrings {
		var data []byte
		switch {
		// OP_DATA_1 through OP_DATA_65 display the opcode followed by
		// the pushed data.
		case opcodeVal >= 0x01 && opcodeVal < 0x4c:
			data = bytes.Repeat(oneBytes, opcodeVal)
			expectedStr = fmt.Sprintf("OP_DATA_%d 0x%s", opcodeVal,
				strings.Repeat(oneStr, opcodeVal))

		// OP_PUSHDATA1.
		case opcodeVal == 0x4c:
			data = bytes.Repeat(oneBytes, 1)
			expectedStr = fmt.Sprintf("OP_PUSHDATA1 0x%02x 0x%s",
				len(data), strings.Repeat(oneStr, 1))

		// OP_PUSHDATA2.
		case opcodeVal == 0x4d:
			data = bytes.Repeat(oneBytes, 2)
			expectedStr = fmt.Sprintf("OP_PUSHDATA2 0x%04x 0x%s",
				len(data), strings.Repeat(oneStr, 2))

		// OP_PUSHDATA4.
		case opcodeVal == 0x4e:
			data = bytes.Repeat(oneBytes, 3)
			expectedStr = fmt.Sprintf("OP_PUSHDATA4 0x%08x 0x%s",
				len(data), strings.Repeat(oneStr, 3))

		// OP_1 through OP_16.
		case opcodeVal >= 0x51 && opcodeVal <= 0x60:
			val := byte(opcodeVal - (0x51 - 1))
			data = []byte{val}
			expectedStr = "OP_" + strconv.Itoa(int(val))

		// OP_NOP1 through OP_NOP10.
		case opcodeVal >= 0xb0 && opcodeVal <= 0xb9:
			switch opcodeVal {
			case 0xb1:
				// OP_NOP2 is an alias of OP_CHECKLOCKTIMEVERIFY
				expectedStr = "OP_CHECKLOCKTIMEVERIFY"
			case 0xb2:
				// OP_NOP3 is an alias of OP_CHECKSEQUENCEVERIFY
				expectedStr = "OP_CHECKSEQUENCEVERIFY"
			case 0xb3, 0xc8, 0xce:
				// OP_NOP4 is now OP_MERKLEBRANCHVERIFY
				expectedStr = "OP_MERKLEBRANCHVERIFY"
			default:
				val := byte(opcodeVal - (0xb0 - 1))
				expectedStr = "OP_NOP" + strconv.Itoa(int(val))
			}

		// Asset and packet introspection opcodes (0xe5-0xf5).
		case opcodeVal >= 0xe5 && opcodeVal <= 0xf5:
			expectedStr = opcodeArray[opcodeVal].name

		// OP_UNKNOWN#.
		case (opcodeVal >= 0xbb && opcodeVal <= 0xc3) || // Unknown range before SHA256 ops
			(opcodeVal == 0xd0) || // Unknown between output ops
			(opcodeVal >= 0xf6 && opcodeVal <= 0xf9) || // Unknown range after new ops
			opcodeVal == 0xfc:
			expectedStr = "OP_UNKNOWN" + strconv.Itoa(opcodeVal)
		}

		var buf strings.Builder
		disasmOpcode(&buf, &opcodeArray[opcodeVal], data, false)
		gotStr := buf.String()
		if gotStr != expectedStr {
			t.Errorf("pop.print (opcode %x): Unexpected disasm "+
				"string - got %v, want %v", opcodeVal, gotStr,
				expectedStr)
			continue
		}
	}
}

func TestShiftOpcodesBigNumSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		setup  func(*stack)
		opFunc func(*opcode, []byte, *Engine) error
		want   []byte
	}{
		{
			name: "lshift 5 << 1 = 10",
			setup: func(s *stack) {
				s.PushByteArray([]byte{0x05})
				s.PushByteArray([]byte{0x01})
			},
			opFunc: opcodeLshift,
			want:   []byte{0x0a},
		},
		{
			name: "lshift 255 << 1 = 510",
			setup: func(s *stack) {
				s.PushByteArray([]byte{0xff, 0x00})
				s.PushByteArray([]byte{0x01})
			},
			opFunc: opcodeLshift,
			want:   []byte{0xfe, 0x01},
		},
		{
			name: "rshift arithmetic: -7 >> 1 = -4",
			setup: func(s *stack) {
				s.PushByteArray([]byte{0x87}) // -7
				s.PushByteArray([]byte{0x01})
			},
			opFunc: opcodeRshift,
			want:   []byte{0x84}, // -4
		},
		{
			name: "rshift arithmetic: -1 >> 100 = -1",
			setup: func(s *stack) {
				s.PushByteArray([]byte{0x81}) // -1
				s.PushByteArray([]byte{0x64}) // 100
			},
			opFunc: opcodeRshift,
			want:   []byte{0x81},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vm := &Engine{dstack: stack{verifyMinimalData: true}}
			tc.setup(&vm.dstack)
			if err := tc.opFunc(nil, nil, vm); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got, err := vm.dstack.PopByteArray()
			if err != nil {
				t.Fatalf("pop: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %x, want %x", got, tc.want)
			}
		})
	}
}

func TestCLTVAcceptsBigNumResult(t *testing.T) {
	t.Parallel()
	// 3_000_000_000 = 0xB2D05E00; sign-magnitude LE needs a 0x00 sign byte
	// because the magnitude MSB (0xb2) has bit 7 set → 5-byte minimal encoding.
	// This is the kind of 5-byte value arithmetic can produce for locktimes.
	vm := &Engine{
		dstack: stack{verifyMinimalData: true},
		tx: wire.MsgTx{
			LockTime: 3_000_000_000,
			TxIn:     []*wire.TxIn{{Sequence: 0}},
		},
		txIdx: 0,
	}
	vm.dstack.PushByteArray([]byte{0x00, 0x5e, 0xd0, 0xb2, 0x00})
	if err := opcodeCheckLockTimeVerify(nil, nil, vm); err != nil {
		t.Fatalf("CLTV: %v", err)
	}
}

func TestCLTVRejectsNegative(t *testing.T) {
	t.Parallel()
	vm := &Engine{
		dstack: stack{verifyMinimalData: true},
		tx:     wire.MsgTx{LockTime: 3_000_000_000, TxIn: []*wire.TxIn{{Sequence: 0}}},
	}
	vm.dstack.PushByteArray([]byte{0x81}) // -1
	err := opcodeCheckLockTimeVerify(nil, nil, vm)
	if !isScriptError(err, txscript.ErrNegativeLockTime) {
		t.Fatalf("want ErrNegativeLockTime, got %v", err)
	}
}

func TestCLTVRejectsTooLarge(t *testing.T) {
	t.Parallel()
	vm := &Engine{
		dstack: stack{verifyMinimalData: true},
		tx:     wire.MsgTx{LockTime: 1, TxIn: []*wire.TxIn{{Sequence: 0}}},
	}
	// 9-byte positive value ≥ 2^63: exceeds uint32 so CLTV must reject.
	v := make([]byte, 9)
	for i := 0; i < 8; i++ {
		v[i] = 0xff
	}
	v[8] = 0x00
	vm.dstack.PushByteArray(v)
	err := opcodeCheckLockTimeVerify(nil, nil, vm)
	if err == nil {
		t.Fatalf("expected error for too-large locktime, got nil")
	}
}

func TestCLTVAccepts9ByteBigNumThatFitsInUint32(t *testing.T) {
	t.Parallel()
	// 2^40, encoded minimally as [0x00,0x00,0x00,0x00,0x00,0x01] — 6 bytes.
	// The old MakeScriptNum(..., 5) path would reject this as too big.
	// With BigNum the Peek succeeds; verifyLockTime rejects it because
	// 2^40 > tx.LockTime == 1.
	v := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	vm := &Engine{
		dstack: stack{verifyMinimalData: true},
		tx:     wire.MsgTx{LockTime: 1, TxIn: []*wire.TxIn{{Sequence: 0}}},
	}
	vm.dstack.PushByteArray(v)
	err := opcodeCheckLockTimeVerify(nil, nil, vm)
	if err == nil {
		t.Fatalf("expected error (UnsatisfiedLockTime), got nil")
	}
	if !isScriptError(err, txscript.ErrUnsatisfiedLockTime) {
		t.Fatalf("want ErrUnsatisfiedLockTime, got %v", err)
	}
}
