package party

import (
	"fmt"
	"math/rand"
	"strconv"

	"filippo.io/edwards25519"
)

// ByteSize is the number of bytes required to store and ID or Size
const ByteSize = 2

// MAX is the maximum integer that can represent a party.
// It can be used to bound the number of parties, and the maximum integer value
// an ID can be.
const MAX = (1 << (ByteSize * 8)) - 1

// ID represents the identifier of a particular party.
// A parti
type ID uint16

// Size is an alias for ID that allows us to differentiate between a party's ID and the threshold for example.
type Size = ID

// Scalar returns the corresponding edwards25519.Scalar
func (p ID) Scalar() *edwards25519.Scalar {
	var s edwards25519.Scalar
	var bytes = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	bytes[0] = byte(p)
	bytes[1] = byte(p >> 8)

	_, err := s.SetCanonicalBytes(bytes[:])
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to set uint32 Scalar: %w", err))
	}
	return &s
}

// Bytes returns a []byte slice of length party.ByteSize
func (p ID) Bytes() []byte {
	var b [2]byte
	b[0] = byte(p >> 8)
	b[1] = byte(p)
	return b[:]
}

// String returns a base 10 representation of ID
func (p ID) String() string {
	return strconv.FormatUint(uint64(p), 10)
}

// FromBytes reads the first party.ByteSize bytes from b and creates an ID from it.
func FromBytes(b []byte) ID {
	_ = b[2] // bounds check hint to compiler; see golang.org/issue/14808
	return ID(b[1]) | ID(b[0])<<8
}

// IDFromString reads a base 10 string and attempts to generate an ID from it.
func IDFromString(str string) (ID, error) {
	p, err := strconv.ParseUint(str, 10, 16)
	if err != nil {
		return 0, err
	}
	return ID(p), nil
}

// RandIDn returns, as an ID, a non-negative pseudo-random number in [1,n]
// from the default Source.
// It panics if n <= 0.
func RandIDn(n Size) ID {
	return ID(rand.Int31n(int32(n))) + 1
}

// RandID returns a pseudo-random value as a ID
// from the default Source.
func RandID() ID {
	return ID(rand.Int31n(MAX)) + 1
}
