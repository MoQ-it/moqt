// Package v22 implements the wire encoding of draft-ietf-moq-transport-22.
//
// Everything that changes between drafts lives in this package so that a
// later draft (or the RFC) can be added as a sibling package.
package v22

import (
	"encoding/binary"
	"io"
	"math/bits"
)

// ALPN is the protocol identifier for this draft, used both as the QUIC
// ALPN and in WebTransport's WT-Available-Protocols.
const ALPN = "moqt-22"

// MaxVarint is the largest value a variable-length integer can carry.
const MaxVarint = 1<<64 - 1

// VarintLen returns the number of bytes of the minimal encoding of v
// (Section 8.1): the count of leading one bits in the first byte gives the
// length, leaving 7 usable bits per byte up to 8 bytes, and 0xff introduces
// a full 64-bit value.
func VarintLen(v uint64) int {
	if v >= 1<<56 {
		return 9
	}
	n := 1
	for v >= 1<<(7*n) {
		n++
	}
	return n
}

// AppendVarint appends the minimal encoding of v to b.
func AppendVarint(b []byte, v uint64) []byte {
	n := VarintLen(v)
	if n == 9 {
		return binary.BigEndian.AppendUint64(append(b, 0xff), v)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	enc := buf[8-n:]
	enc[0] |= ^byte(0xff >> (n - 1))
	return append(b, enc...)
}

// ParseVarint decodes a variable-length integer from the start of b and
// returns it with the number of bytes consumed. Non-minimal encodings are
// valid and accepted.
func ParseVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := bits.LeadingZeros8(^b[0]) + 1
	if len(b) < n {
		return 0, 0, io.ErrUnexpectedEOF
	}
	if n == 9 {
		return binary.BigEndian.Uint64(b[1:9]), 9, nil
	}
	v := uint64(b[0] & (0xff >> n))
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n, nil
}

// ReadVarint decodes a variable-length integer from r. It returns io.EOF
// only if r is at EOF before the first byte.
func ReadVarint(r io.ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := bits.LeadingZeros8(^first) + 1
	var v uint64
	if n < 9 {
		v = uint64(first & (0xff >> n))
	}
	for i := 1; i < n; i++ {
		c, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		v = v<<8 | uint64(c)
	}
	return v, nil
}
