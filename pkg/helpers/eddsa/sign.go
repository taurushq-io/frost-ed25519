package eddsa

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// Compute the SHA 512 of the message
func ComputeMessageHash(message []byte) []byte {
	digest := sha512.Sum512(message)
	return digest[:]
}

// ComputeChallenge computes the value H(Ri, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(R, groupKey *edwards25519.Point, message []byte) *edwards25519.Scalar {
	var s edwards25519.Scalar

	h := sha512.New()
	_, _ = h.Write(R.Bytes())
	_, _ = h.Write(groupKey.Bytes())
	_, _ = h.Write(message)
	s.SetUniformBytes(h.Sum(nil))

	return &s
}
