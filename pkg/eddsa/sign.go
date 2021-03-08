package eddsa

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// ComputeChallenge computes the value H(R, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(R *edwards25519.Point, groupKey *PublicKey, message []byte) *edwards25519.Scalar {
	var s edwards25519.Scalar

	data := make([]byte, 0, 64+len(message))
	data = append(data, R.Bytes()...)
	data = append(data, groupKey.Point().Bytes()...)
	data = append(data, message...)
	digest := sha512.Sum512(data)
	s.SetUniformBytes(digest[:])

	return &s
}
