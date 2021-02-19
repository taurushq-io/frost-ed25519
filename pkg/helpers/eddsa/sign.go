package eddsa

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// Compute the SHA 512 of the message
func ComputeMessageHash(message []byte) []byte {
	var out [64]byte
	h := sha512.New()
	b, err := h.Write(message)
	if (err != nil || b != len(message)) {
		panic("hash failed")
	} 
	h.Sum(out[:0])
	return out[:]
}

// ComputeChallenge computes the value H(Ri, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(message []byte, groupKey, R *edwards25519.Point) *edwards25519.Scalar {
	var s edwards25519.Scalar
	return SetChallenge(&s, message, groupKey, R)
}

// SetChallenge set s to the edwards25519.Scalar value of H(Ri, A, M).
func SetChallenge(s *edwards25519.Scalar, message []byte, groupKey, R *edwards25519.Point) *edwards25519.Scalar {
	//var kHash [64]byte

	h := sha512.New()
	b, err := h.Write(R.Bytes())
	if (err != nil || b != len(R.Bytes())) {
		panic("hash failed")
	} 
	b, err = h.Write(groupKey.Bytes())
	if (err != nil || b != len(groupKey.Bytes())) {
		panic("hash failed")
	} 
	b, err = h.Write(message)
	if (err != nil || b != len(message)) {
		panic("hash failed")
	} 
	//h.Sum(kHash[:0])
	s.SetUniformBytes(h.Sum(nil))
	//s.SetUniformBytes(kHash[:])
	return s
}
