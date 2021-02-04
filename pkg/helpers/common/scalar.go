package common

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
)

func NewScalarRandom() *edwards25519.Scalar {
	var s edwards25519.Scalar
	bytes := make([]byte, 64)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err))
	}
	return s.SetUniformBytes(bytes)
}

func NewScalarUInt32(x uint32) *edwards25519.Scalar {
	var s edwards25519.Scalar
	bytes := make([]byte, 32)
	bytes[0] = byte(x)
	bytes[1] = byte(x >> 8)
	bytes[2] = byte(x >> 16)
	bytes[3] = byte(x >> 24)
	_, _ = s.SetCanonicalBytes(bytes)
	return &s
}
