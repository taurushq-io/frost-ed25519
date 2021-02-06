package common

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
)

// SetScalarRandom resets s to a random edwards25519.Scalar using the default randomness source from crypto/rand
func SetScalarRandom(s *edwards25519.Scalar) *edwards25519.Scalar {
	var err error
	var bytes [64]byte

	_, err = rand.Read(bytes[:])
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err))
	}
	return s.SetUniformBytes(bytes[:])
}

// NewScalarRandom generates a new edwards25519.Scalar using the default randomness source from crypto/rand
func NewScalarRandom() *edwards25519.Scalar {
	var s edwards25519.Scalar

	return SetScalarRandom(&s)
}

// SetScalarUInt32 set s's value to that of a uint32 x. It creates a 32 byte big-endian representation of x,
// which is set by s.SetCanonicalBytes .
func SetScalarUInt32(s *edwards25519.Scalar, x uint32) *edwards25519.Scalar {
	var err error

	var bytes = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	bytes[0] = byte(x)
	bytes[1] = byte(x >> 8)
	bytes[2] = byte(x >> 16)
	bytes[3] = byte(x >> 24)

	_, err = s.SetCanonicalBytes(bytes[:])
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to set uint32 Scalar: %w", err))
	}
	return s
}

// NewScalarUInt32 generates a edwards25519.Scalar with the value of x.
// It constructs a 32-byte big-endian representation of x.
func NewScalarUInt32(x uint32) *edwards25519.Scalar {
	var s edwards25519.Scalar

	return SetScalarUInt32(&s, x)
}
