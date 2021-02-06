package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// PrivateKey is created from an ed25519.PrivateKey and remembers the seed
// in order to go back to that format
type PrivateKey struct {
	edwards25519.Scalar
	pk *PublicKey
}

func NewPrivateKey(key ed25519.PrivateKey) *PrivateKey {
	var (
		sk PrivateKey
		pk PublicKey
	)

	digest := sha512.Sum512(key[:32])

	sk.SetBytesWithClamping(digest[:32])

	pk.Point.ScalarBaseMult(&sk.Scalar)
	sk.pk = &pk
	return &sk
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}
