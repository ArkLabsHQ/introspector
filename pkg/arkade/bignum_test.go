package arkade

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/txscript"
)

// testMaxBigNumLen is the arithmetic-operand byte ceiling used across all
// BigNum opcodes: 520 bytes, matching txscript.MaxScriptElementSize.
const testMaxBigNumLen = 520

func TestMakeBigNumDecoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		wantInt64  int64 // meaningful only when wantUseBig == false
		wantUseBig bool
		wantBigHex string // hex of absolute magnitude; sign encoded in wantSign
		wantSign   int    // -1, 0, 1 (big.Int.Sign())
	}{
		{"zero empty", nil, 0, false, "", 0},
		{"one", []byte{0x01}, 1, false, "", 0},
		{"neg one", []byte{0x81}, -1, false, "", 0},
		{"127", []byte{0x7f}, 127, false, "", 0},
		{"128", []byte{0x80, 0x00}, 128, false, "", 0},
		{"neg 128", []byte{0x80, 0x80}, -128, false, "", 0},
		// int64 boundary (max positive and min negative that fit in 8
		// minimally-encoded bytes)
		{"int64 max 8 bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, 9223372036854775807, false, "", 0},
		{"int64 min plus one 8 bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, -9223372036854775807, false, "", 0},
		// 9 bytes → big path. 2^63 has magnitude requiring 9 bytes
		// (sign-extension byte).
		{"2^63 as 9 bytes", nil, 0, true, "8000000000000000", 1},
		{"-2^63 as 9 bytes", nil, 0, true, "8000000000000000", -1},
	}

	// Encode the 9-byte fixtures properly.
	twoPow63 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}
	negTwoPow63 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80}

	for i := range tests {
		if tests[i].name == "2^63 as 9 bytes" {
			tests[i].serialized = twoPow63
		}
		if tests[i].name == "-2^63 as 9 bytes" {
			tests[i].serialized = negTwoPow63
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MakeBigNum(tc.serialized, true, testMaxBigNumLen)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.useBig != tc.wantUseBig {
				t.Fatalf("useBig = %v, want %v", got.useBig, tc.wantUseBig)
			}
			if !tc.wantUseBig {
				if got.small != tc.wantInt64 {
					t.Fatalf("small = %d, want %d", got.small, tc.wantInt64)
				}
				return
			}
			if got.big == nil {
				t.Fatalf("big is nil")
			}
			wantMag, _ := new(big.Int).SetString(tc.wantBigHex, 16)
			gotMag := new(big.Int).Abs(got.big)
			if gotMag.Cmp(wantMag) != 0 {
				t.Fatalf("big magnitude = %s, want %s", gotMag.Text(16), tc.wantBigHex)
			}
			if got.big.Sign() != tc.wantSign {
				t.Fatalf("sign = %d, want %d", got.big.Sign(), tc.wantSign)
			}
		})
	}
}

func TestMakeBigNumRejectsOversized(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, 521)
	_, err := MakeBigNum(oversized, true, testMaxBigNumLen)
	if err == nil {
		t.Fatalf("expected error for 521-byte operand")
	}
	if !isScriptError(err, txscript.ErrNumberTooBig) {
		t.Fatalf("want ErrNumberTooBig, got %v", err)
	}
}

func TestMakeBigNumRejectsNonMinimal(t *testing.T) {
	t.Parallel()
	// Non-minimal: [0x01, 0x00] should be [0x01].
	_, err := MakeBigNum([]byte{0x01, 0x00}, true, testMaxBigNumLen)
	if !isScriptError(err, txscript.ErrMinimalData) {
		t.Fatalf("want ErrMinimalData, got %v", err)
	}
	// Negative zero is not minimal.
	_, err = MakeBigNum([]byte{0x80}, true, testMaxBigNumLen)
	if !isScriptError(err, txscript.ErrMinimalData) {
		t.Fatalf("want ErrMinimalData for negative zero, got %v", err)
	}
	// Without the flag, non-minimal input is accepted.
	n, err := MakeBigNum([]byte{0x01, 0x00}, false, testMaxBigNumLen)
	if err != nil || n.useBig || n.small != 1 {
		t.Fatalf("non-minimal path: got (%+v, %v)", n, err)
	}
}

// isScriptError reports whether err is a txscript.Error with the given code.
func isScriptError(err error, code txscript.ErrorCode) bool {
	if err == nil {
		return false
	}
	asErr, ok := err.(txscript.Error)
	if !ok {
		return false
	}
	return asErr.ErrorCode == code
}

func TestBigNumBytesEncoding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  BigNum
		want []byte
	}{
		{"zero int64", BigNumFromInt64(0), nil},
		{"one", BigNumFromInt64(1), []byte{0x01}},
		{"neg one", BigNumFromInt64(-1), []byte{0x81}},
		{"127", BigNumFromInt64(127), []byte{0x7f}},
		{"128", BigNumFromInt64(128), []byte{0x80, 0x00}},
		{"neg 128", BigNumFromInt64(-128), []byte{0x80, 0x80}},
		{"255", BigNumFromInt64(255), []byte{0xff, 0x00}},
		{"neg 255", BigNumFromInt64(-255), []byte{0xff, 0x80}},
		{"int64 max", BigNumFromInt64(9223372036854775807), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		{"int64 min plus one", BigNumFromInt64(-9223372036854775807), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.src.Bytes()
			if err != nil {
				t.Fatalf("Bytes() error: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("Bytes() = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestBigNumBytesBigPath(t *testing.T) {
	t.Parallel()
	// 2^63 as big.Int → minimal sign-magnitude LE is 9 bytes: magnitude plus
	// 0x00 sign ext.
	n := BigNum{big: new(big.Int).SetUint64(1 << 63), useBig: true}
	got, err := n.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("Bytes() = %x, want %x", got, want)
	}
	// -(2^63)
	neg := BigNum{big: new(big.Int).Neg(new(big.Int).SetUint64(1 << 63)), useBig: true}
	got, err = neg.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	want = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80}
	if !bytes.Equal(got, want) {
		t.Fatalf("Bytes() = %x, want %x", got, want)
	}
}

func TestBigNumBytesExceedsLimit(t *testing.T) {
	t.Parallel()
	// Construct a magnitude of 1 << (520*8) which requires 521 bytes as
	// sign-magnitude LE.
	magnitude := new(big.Int).Lsh(big.NewInt(1), 520*8)
	n := BigNum{big: magnitude, useBig: true}
	_, err := n.Bytes()
	if !isScriptError(err, txscript.ErrNumberTooBig) {
		t.Fatalf("want ErrNumberTooBig, got %v", err)
	}
}

func TestBigNumFromUint64(t *testing.T) {
	t.Parallel()
	// Values that fit in int64 positive range use int64 path.
	n := BigNumFromUint64(12345)
	if n.useBig {
		t.Fatalf("small uint64 should be on int64 path")
	}
	if n.small != 12345 {
		t.Fatalf("small = %d, want 12345", n.small)
	}
	// Value at uint64 max (> int64 max) must use big path.
	n = BigNumFromUint64(^uint64(0))
	if !n.useBig {
		t.Fatalf("max uint64 must use big path")
	}
	want := new(big.Int).SetUint64(^uint64(0))
	if n.big.Cmp(want) != 0 {
		t.Fatalf("big = %s, want %s", n.big, want)
	}
}
