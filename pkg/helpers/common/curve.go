package common

import (
	"crypto/rand"
	"filippo.io/edwards25519"
	"fmt"
)

func NewScalarRandom() (*edwards25519.Scalar, error) {
	bytes := make([]byte, 64)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err)
	}
	return new(edwards25519.Scalar).SetUniformBytes(bytes), nil
}

func NewScalarUInt32(x uint32) (*edwards25519.Scalar, error) {
	bytes := make([]byte, 32)
	bytes[0] = byte(x)
	bytes[1] = byte(x >> 8)
	bytes[2] = byte(x >> 16)
	bytes[3] = byte(x >> 24)
	return new(edwards25519.Scalar).SetCanonicalBytes(bytes)
}
