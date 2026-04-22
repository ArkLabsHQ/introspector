package arkade

import (
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/txscript"
)

// maxBigNumLen is the largest permitted byte-length of a minimally-encoded
// BigNum operand or result. Equal to txscript.MaxScriptElementSize.
const maxBigNumLen = txscript.MaxScriptElementSize

// int64ByteCap is the largest byte length whose minimal sign-magnitude LE
// encoding is guaranteed to fit in int64. 9+ bytes require the big.Int path.
const int64ByteCap = 8

// BigNum is the unified numeric type used by the arkade VM. It is a tagged
// union: when useBig is false the value lives in small (fast path). When
// useBig is true the value lives in big (arbitrary precision). Promotion
// from small → big is one-way; an arithmetic result that fits in int64
// after having been produced on the big path is NOT demoted.
type BigNum struct {
	small  int64
	big    *big.Int
	useBig bool
}

// BigNumFromInt64 constructs a BigNum on the int64 fast path.
func BigNumFromInt64(v int64) BigNum {
	return BigNum{small: v}
}

// BigNumFromUint64 constructs a BigNum from an unsigned 64-bit value. Values
// up to math.MaxInt64 use the int64 fast path; larger values promote to big.
func BigNumFromUint64(v uint64) BigNum {
	const int64Max = uint64(1<<63 - 1)
	if v <= int64Max {
		return BigNum{small: int64(v)}
	}
	return BigNum{big: new(big.Int).SetUint64(v), useBig: true}
}

// MakeBigNum decodes a sign-magnitude little-endian byte slice into a BigNum.
// If requireMinimal is true, inputs that are not minimally encoded are
// rejected (including the negative-zero encoding [0x80]). If len(v) > maxLen
// an ErrNumberTooBig is returned.
//
// Values with len(v) ≤ 8 land on the int64 fast path; ≥ 9 bytes land on the
// big.Int path.
func MakeBigNum(v []byte, requireMinimal bool, maxLen int) (BigNum, error) {
	if len(v) > maxLen {
		return BigNum{}, scriptError(txscript.ErrNumberTooBig,
			fmt.Sprintf("numeric value encoded as %x is %d bytes which exceeds the max allowed of %d",
				v, len(v), maxLen))
	}
	if requireMinimal {
		if err := checkMinimalDataEncoding(v); err != nil {
			return BigNum{}, err
		}
	}
	if len(v) == 0 {
		return BigNum{}, nil
	}
	if len(v) <= int64ByteCap {
		return decodeInt64(v), nil
	}
	return decodeBig(v), nil
}

// decodeInt64 parses up to 8 bytes of sign-magnitude LE into int64.
// Pre: 1 ≤ len(v) ≤ 8.
func decodeInt64(v []byte) BigNum {
	var result int64
	for i, b := range v {
		result |= int64(b) << uint(8*i)
	}
	// Strip sign bit from most significant byte and apply sign.
	if v[len(v)-1]&0x80 != 0 {
		result &= ^(int64(0x80) << uint(8*(len(v)-1)))
		return BigNum{small: -result}
	}
	return BigNum{small: result}
}

// decodeBig parses ≥ 9 bytes of sign-magnitude LE into a *big.Int.
// Pre: len(v) ≥ 9.
func decodeBig(v []byte) BigNum {
	msb := v[len(v)-1]
	negative := msb&0x80 != 0
	mag := make([]byte, len(v))
	copy(mag, v)
	mag[len(mag)-1] = msb & 0x7f
	// Reverse to big-endian for big.Int.SetBytes.
	for i, j := 0, len(mag)-1; i < j; i, j = i+1, j-1 {
		mag[i], mag[j] = mag[j], mag[i]
	}
	b := new(big.Int).SetBytes(mag)
	if negative {
		b.Neg(b)
	}
	return BigNum{big: b, useBig: true}
}

// Bytes returns the minimal sign-magnitude little-endian encoding of n.
// If the encoding would exceed maxBigNumLen, an ErrNumberTooBig is returned.
func (n BigNum) Bytes() ([]byte, error) {
	var out []byte
	if !n.useBig {
		out = encodeInt64(n.small)
	} else {
		out = encodeBig(n.big)
	}
	if len(out) > maxBigNumLen {
		return nil, scriptError(txscript.ErrNumberTooBig,
			fmt.Sprintf("BigNum result encoded as %d bytes exceeds max allowed of %d",
				len(out), maxBigNumLen))
	}
	return out, nil
}

// encodeInt64 reproduces the legacy scriptNum.Bytes() algorithm for int64.
func encodeInt64(v int64) []byte {
	if v == 0 {
		return nil
	}
	neg := v < 0
	if neg {
		v = -v
	}
	result := make([]byte, 0, 9)
	for v > 0 {
		result = append(result, byte(v&0xff))
		v >>= 8
	}
	if result[len(result)-1]&0x80 != 0 {
		extra := byte(0x00)
		if neg {
			extra = 0x80
		}
		result = append(result, extra)
	} else if neg {
		result[len(result)-1] |= 0x80
	}
	return result
}

// encodeBig serialises a *big.Int as minimal sign-magnitude LE.
func encodeBig(v *big.Int) []byte {
	if v.Sign() == 0 {
		return nil
	}
	mag := new(big.Int).Abs(v).Bytes() // big-endian magnitude
	le := make([]byte, len(mag))
	for i, b := range mag {
		le[len(mag)-1-i] = b
	}
	neg := v.Sign() < 0
	if le[len(le)-1]&0x80 != 0 {
		extra := byte(0x00)
		if neg {
			extra = 0x80
		}
		le = append(le, extra)
	} else if neg {
		le[len(le)-1] |= 0x80
	}
	return le
}

// IsZero reports whether n equals zero.
func (n BigNum) IsZero() bool {
	if !n.useBig {
		return n.small == 0
	}
	return n.big.Sign() == 0
}

// Sign returns -1, 0, or +1.
func (n BigNum) Sign() int {
	if !n.useBig {
		switch {
		case n.small < 0:
			return -1
		case n.small > 0:
			return 1
		}
		return 0
	}
	return n.big.Sign()
}

// Cmp reports -1/0/+1 comparing n and m.
func (n BigNum) Cmp(m BigNum) int {
	if !n.useBig && !m.useBig {
		switch {
		case n.small < m.small:
			return -1
		case n.small > m.small:
			return 1
		}
		return 0
	}
	return n.asBig().Cmp(m.asBig())
}

// asBig materialises a *big.Int view of n regardless of current path.
func (n BigNum) asBig() *big.Int {
	if n.useBig {
		return n.big
	}
	return big.NewInt(n.small)
}
