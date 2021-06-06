package scalar

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// SetScalarRandom sets s to a random ristretto.Scalar using the default randomness source from crypto/rand
func SetScalarRandom(s *ristretto.Scalar) *ristretto.Scalar {
	bytes := make([]byte, 64)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err))
	}

	_, _ = s.SetUniformBytes(bytes)
	return s
}

// NewScalarRandom generates a new ristretto.Scalar using the default randomness source from crypto/rand
func NewScalarRandom() *ristretto.Scalar {
	var s ristretto.Scalar
	return SetScalarRandom(&s)
}

// SetScalarUInt32 set s's value to that of a uint32 x. It creates a 32 byte big-endian representation of x,
// which is set by s.SetCanonicalBytes .
func SetScalarUInt32(s *ristretto.Scalar, x uint32) *ristretto.Scalar {
	bytes := make([]byte, 32)

	bytes[0] = byte(x)
	bytes[1] = byte(x >> 8)
	bytes[2] = byte(x >> 16)
	bytes[3] = byte(x >> 24)

	_, err := s.SetCanonicalBytes(bytes)
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to set uint32 Scalar: %w", err))
	}
	return s
}

// NewScalarUInt32 generates a ristretto.Scalar with the value of x.
// It constructs a 32-byte big-endian representation of x.
func NewScalarUInt32(x uint32) *ristretto.Scalar {
	var s ristretto.Scalar

	return SetScalarUInt32(&s, x)
}
