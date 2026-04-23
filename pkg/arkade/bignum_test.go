package arkade

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/txscript"
)

func TestBigNumFromBytesDecoding(t *testing.T) {
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
		{"int64 max 8 bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, math.MaxInt64, false, "", 0},
		{"int64 min plus one 8 bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MinInt64 + 1, false, "", 0},
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
			got, err := BigNumFromBytes(tc.serialized)
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

func TestBigNumFromBytesRejectsOversized(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, maxBigNumLen+1)
	_, err := BigNumFromBytes(oversized)
	if err == nil {
		t.Fatalf("expected error for %d-byte operand", maxBigNumLen+1)
	}
	if !isScriptError(err, txscript.ErrNumberTooBig) {
		t.Fatalf("want ErrNumberTooBig, got %v", err)
	}
}

func TestBigNumFromBytesRejectsNonMinimal(t *testing.T) {
	t.Parallel()
	// Non-minimal: [0x01, 0x00] should be [0x01].
	_, err := BigNumFromBytes([]byte{0x01, 0x00})
	if !isScriptError(err, txscript.ErrMinimalData) {
		t.Fatalf("want ErrMinimalData, got %v", err)
	}
	// Negative zero is not minimal.
	_, err = BigNumFromBytes([]byte{0x80})
	if !isScriptError(err, txscript.ErrMinimalData) {
		t.Fatalf("want ErrMinimalData for negative zero, got %v", err)
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
		{"int64 max", BigNumFromInt64(math.MaxInt64), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		{"int64 min plus one", BigNumFromInt64(math.MinInt64 + 1), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
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

func TestBigNumFixedBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		src        BigNum
		size       int
		want       []byte
		shouldFail bool
	}{
		{"5 as 4 bytes", BigNumFromInt64(5), 4, []byte{0x05, 0x00, 0x00, 0x00}, false},
		{"-5 as 4 bytes", BigNumFromInt64(-5), 4, []byte{0x05, 0x00, 0x00, 0x80}, false},
		{"-5 as 1 byte", BigNumFromInt64(-5), 1, []byte{0x85}, false},
		{"0 as 4 bytes", BigNumFromInt64(0), 4, []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"0 as 0 bytes", BigNumFromInt64(0), 0, []byte{}, false},
		{"128 as 2 bytes", BigNumFromInt64(128), 2, []byte{0x80, 0x00}, false},
		{"-128 as 2 bytes", BigNumFromInt64(-128), 2, []byte{0x80, 0x80}, false},
		{"255 as 1 byte fails", BigNumFromInt64(255), 1, nil, true},
		{"128 as 1 byte fails", BigNumFromInt64(128), 1, nil, true},
		{"negative size fails", BigNumFromInt64(0), -1, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.src.FixedBytes(tc.size)
			if tc.shouldFail {
				if err == nil {
					t.Fatalf("expected failure, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("FixedBytes: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("FixedBytes() = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestDecodeInt64AcceptsEmptyZero(t *testing.T) {
	t.Parallel()

	got := decodeInt64(encodeInt64(0))
	if got.useBig || got.small != 0 {
		t.Fatalf("decodeInt64(encodeInt64(0)) = %+v, want zero on int64 path", got)
	}
}

func TestInt64EncodingRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []int64{
		math.MinInt64,
		math.MinInt64 + 1,
		-1,
		0,
		1,
		math.MaxInt64,
	}
	for _, want := range tests {
		t.Run(fmt.Sprintf("%d", want), func(t *testing.T) {
			got, err := BigNumFromBytes(encodeInt64(want))
			if err != nil {
				t.Fatalf("BigNumFromBytes: %v", err)
			}
			if got.BigInt().Cmp(big.NewInt(want)) != 0 {
				t.Fatalf("roundtrip = %s, want %d", got.BigInt(), want)
			}
		})
	}
}

func TestBigIntEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	maxInt64PlusOne := new(big.Int).SetUint64(math.MaxInt64 + 1)
	minInt64MinusOne := new(big.Int).Neg(new(big.Int).SetUint64(math.MaxInt64 + 2))
	maxUint64PlusOne := new(big.Int).Add(new(big.Int).SetUint64(math.MaxUint64), big.NewInt(1))

	max520ByteMagnitude := new(big.Int).Lsh(big.NewInt(1), uint(maxBigNumLen*8-2))
	negMax520ByteMagnitude := new(big.Int).Neg(new(big.Int).Set(max520ByteMagnitude))

	tests := []struct {
		name string
		want *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"max int64", big.NewInt(math.MaxInt64)},
		{"max int64 plus one", maxInt64PlusOne},
		{"min int64", big.NewInt(math.MinInt64)},
		{"min int64 minus one", minInt64MinusOne},
		{"max uint64", new(big.Int).SetUint64(math.MaxUint64)},
		{"max uint64 plus one", maxUint64PlusOne},
		{"max 520-byte positive", max520ByteMagnitude},
		{"max 520-byte negative", negMax520ByteMagnitude},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := BigNum{big: new(big.Int).Set(tc.want), useBig: true}
			encoded, err := src.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			got, err := BigNumFromBytes(encoded)
			if err != nil {
				t.Fatalf("BigNumFromBytes: %v", err)
			}
			if got.BigInt().Cmp(tc.want) != 0 {
				t.Fatalf("roundtrip = %s, want %s", got.BigInt(), tc.want)
			}
		})
	}
}

func TestBigNumBytesBigPath(t *testing.T) {
	t.Parallel()
	// 2^63 as big.Int → minimal sign-magnitude LE is 9 bytes: magnitude plus
	// 0x00 sign ext.
	n := BigNum{big: new(big.Int).SetUint64(math.MaxInt64 + 1), useBig: true}
	got, err := n.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("Bytes() = %x, want %x", got, want)
	}
	// -(2^63)
	neg := BigNum{big: new(big.Int).Neg(new(big.Int).SetUint64(math.MaxInt64 + 1)), useBig: true}
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
	// Value at int64 max still uses the int64 path.
	n = BigNumFromUint64(math.MaxInt64)
	if n.useBig {
		t.Fatalf("max int64 should be on int64 path")
	}
	if n.small != math.MaxInt64 {
		t.Fatalf("small = %d, want %d", n.small, math.MaxInt64)
	}
	// Value just above int64 max must use big path.
	n = BigNumFromUint64(math.MaxInt64 + 1)
	if !n.useBig {
		t.Fatalf("max int64 plus one must use big path")
	}
	want := new(big.Int).SetUint64(math.MaxInt64 + 1)
	if n.big.Cmp(want) != 0 {
		t.Fatalf("big = %s, want %s", n.big, want)
	}
	// Value at uint64 max (> int64 max) must use big path.
	n = BigNumFromUint64(math.MaxUint64)
	if !n.useBig {
		t.Fatalf("max uint64 must use big path")
	}
	want = new(big.Int).SetUint64(math.MaxUint64)
	if n.big.Cmp(want) != 0 {
		t.Fatalf("big = %s, want %s", n.big, want)
	}
}

func TestBigNumAddFastPath(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(2)
	b := BigNumFromInt64(3)
	got := a.Add(b)
	if got.useBig || got.small != 5 {
		t.Fatalf("got %+v, want small=5", got)
	}
}

func TestBigNumAddOverflowPromotes(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(math.MaxInt64)
	b := BigNumFromInt64(1)
	got := a.Add(b)
	if !got.useBig {
		t.Fatalf("expected promotion to big, got %+v", got)
	}
	want := new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
	if got.big.Cmp(want) != 0 {
		t.Fatalf("got %s, want %s", got.big, want)
	}
}

func TestBigNumSubOverflowPromotes(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(math.MinInt64)
	b := BigNumFromInt64(1)
	got := a.Sub(b)
	if !got.useBig {
		t.Fatalf("expected promotion, got %+v", got)
	}
}

func TestBigNumMulFastPathAndOverflow(t *testing.T) {
	t.Parallel()
	got := BigNumFromInt64(1_000_000).Mul(BigNumFromInt64(1_000_000))
	if got.useBig || got.small != 1_000_000_000_000 {
		t.Fatalf("unexpected small-path result %+v", got)
	}
	big1 := BigNumFromInt64(1 << 32)
	got = big1.Mul(big1) // 2^64, overflows int64
	if !got.useBig {
		t.Fatalf("expected promotion for 2^32 * 2^32, got %+v", got)
	}
	want := new(big.Int).Lsh(big.NewInt(1), 64)
	if got.big.Cmp(want) != 0 {
		t.Fatalf("got %s, want 2^64", got.big)
	}
}

func TestBigNumDivAndModSignSemantics(t *testing.T) {
	t.Parallel()
	// Truncated division: sign of remainder follows dividend.
	q, err := BigNumFromInt64(-7).Div(BigNumFromInt64(2))
	if err != nil {
		t.Fatalf("Div: %v", err)
	}
	r, err := BigNumFromInt64(-7).Mod(BigNumFromInt64(2))
	if err != nil {
		t.Fatalf("Mod: %v", err)
	}
	if q.small != -3 || r.small != -1 {
		t.Fatalf("got q=%d r=%d, want q=-3 r=-1", q.small, r.small)
	}
	// 7 / -2 = -3 (truncated), 7 % -2 = 1.
	q, err = BigNumFromInt64(7).Div(BigNumFromInt64(-2))
	if err != nil {
		t.Fatalf("Div: %v", err)
	}
	r, err = BigNumFromInt64(7).Mod(BigNumFromInt64(-2))
	if err != nil {
		t.Fatalf("Mod: %v", err)
	}
	if q.small != -3 || r.small != 1 {
		t.Fatalf("got q=%d r=%d, want q=-3 r=1", q.small, r.small)
	}
}

func TestBigNumDivAndModByZero(t *testing.T) {
	t.Parallel()

	_, err := BigNumFromInt64(7).Div(BigNumFromInt64(0))
	if !errors.Is(err, errBigNumDivisionByZero) {
		t.Fatalf("Div by zero: want errBigNumDivisionByZero, got %v", err)
	}

	_, err = BigNumFromInt64(7).Mod(BigNumFromInt64(0))
	if !errors.Is(err, errBigNumModuloByZero) {
		t.Fatalf("Mod by zero: want errBigNumModuloByZero, got %v", err)
	}
}

func TestBigNumNegateOverflowPromotes(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(math.MinInt64)
	got := a.Negate()
	if !got.useBig {
		t.Fatalf("expected promotion, got %+v", got)
	}
	want := new(big.Int).Neg(big.NewInt(math.MinInt64))
	if got.big.Cmp(want) != 0 {
		t.Fatalf("got %s, want %s", got.big, want)
	}
}

func TestBigNumAbs(t *testing.T) {
	t.Parallel()
	if BigNumFromInt64(-5).Abs().small != 5 {
		t.Fatalf("abs(-5) wrong")
	}
	// abs of int64 min must promote.
	got := BigNumFromInt64(math.MinInt64).Abs()
	if !got.useBig {
		t.Fatalf("abs(int64 min) must promote")
	}
}

func TestBigNumLshift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, shift, want int64
	}{
		{1, 0, 1},
		{1, 8, 256},
		{-1, 8, -256},
		{5, 1, 10},
		{-5, 1, -10},
		{0, 100, 0},
	}
	for _, tc := range tests {
		got, err := BigNumFromInt64(tc.in).Lshift(uint(tc.shift))
		if err != nil {
			t.Fatalf("Lshift(%d, %d): %v", tc.in, tc.shift, err)
		}
		if got.useBig {
			if got.BigInt().Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("Lshift(%d, %d) big = %s, want %d", tc.in, tc.shift, got.big, tc.want)
			}
			continue
		}
		if got.small != tc.want {
			t.Fatalf("Lshift(%d, %d) small = %d, want %d", tc.in, tc.shift, got.small, tc.want)
		}
	}
}

func TestBigNumLshiftExceeds520Bytes(t *testing.T) {
	t.Parallel()
	// Shifting a non-zero value by enough to exceed 520*8 = 4160 bits
	// produces a magnitude that can't fit in 520 bytes.
	_, err := BigNumFromInt64(1).Lshift(4161)
	if !isScriptError(err, txscript.ErrNumberTooBig) {
		t.Fatalf("want ErrNumberTooBig, got %v", err)
	}
}

func TestBigNumRshiftArithmetic(t *testing.T) {
	t.Parallel()
	// Arithmetic shift: rounds toward negative infinity for negatives.
	tests := []struct {
		in, shift, want int64
	}{
		{7, 1, 3},
		{-7, 1, -4}, // -4 (floor(-3.5) = -4)
		{-1, 1, -1}, // -1 >> any = -1
		{-1, 100, -1},
		{8, 3, 1},
		{-8, 3, -1},
		{-9, 3, -2}, // floor(-1.125) = -2
		{0, 10, 0},
	}
	for _, tc := range tests {
		got := BigNumFromInt64(tc.in).Rshift(uint(tc.shift))
		if got.BigInt().Cmp(big.NewInt(tc.want)) != 0 {
			t.Fatalf("Rshift(%d, %d) = %s, want %d", tc.in, tc.shift, got.BigInt(), tc.want)
		}
	}
}

func TestMinimallyEncode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want []byte
	}{
		{nil, nil},
		{[]byte{}, nil},
		{[]byte{0x05, 0x00, 0x00, 0x00}, []byte{0x05}},
		{[]byte{0x00, 0x00, 0x00, 0x80}, nil},          // negative zero → zero
		{[]byte{0x05, 0x00, 0x00, 0x80}, []byte{0x85}}, // -5 padded
		{[]byte{0x05}, []byte{0x05}},                   // already minimal
		{[]byte{0x80, 0x00}, []byte{0x80, 0x00}},       // 128 needs sign-ext byte
		{[]byte{0x80, 0x00, 0x00}, []byte{0x80, 0x00}}, // 128 with extra padding
		{[]byte{0x00, 0x80}, nil},                      // -0 two-byte → zero
	}
	for i, tc := range tests {
		got := minimallyEncode(tc.in)
		want := tc.want
		if want == nil {
			want = []byte{}
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: minimallyEncode(%x) = %x, want %x", i, tc.in, got, want)
		}
	}
}
