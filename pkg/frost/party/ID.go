package party

import (
	"fmt"
	"math/rand"
	"strconv"

	"filippo.io/edwards25519"
)

const ByteSize = 4

type (
	ID   uint32
	Size = ID
)

func (p ID) Scalar() *edwards25519.Scalar {
	var s edwards25519.Scalar
	var bytes = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	bytes[0] = byte(p)
	bytes[1] = byte(p >> 8)
	bytes[2] = byte(p >> 16)
	bytes[3] = byte(p >> 24)

	_, err := s.SetCanonicalBytes(bytes[:])
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to set uint32 Scalar: %w", err))
	}
	return &s
}

func (p ID) Bytes() []byte {
	var b [4]byte
	b[0] = byte(p >> 24)
	b[1] = byte(p >> 16)
	b[2] = byte(p >> 8)
	b[3] = byte(p)
	return b[:]
}

func FromBytes(b []byte) ID {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return ID(b[3]) | ID(b[2])<<8 | ID(b[1])<<16 | ID(b[0])<<24
}

func IDFromString(str string) (ID, error) {
	p, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0, err
	}
	return ID(p), nil
}

// RandIDn returns, as an ID, a non-negative pseudo-random number in [1,n)
// from the default Source.
// It panics if n <= 0.
func RandIDn(n Size) ID {
	return ID(rand.Int31n(int32(n))) + 1
}

// RandID returns a pseudo-random 32-bit value as a ID
// from the default Source.
func RandID() ID {
	return ID(rand.Uint32()) + 1
}

func (p ID) Size() int {
	return 4
}
