package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// PublicKey represents a FROST-Ed25519 verification key.
type PublicKey struct {
	pk edwards25519.Point
}

// NewPublicKeyFromPoint returns a PublicKey given an edwards25519.Point.
func NewPublicKeyFromPoint(public *edwards25519.Point) *PublicKey {
	var pk PublicKey

	pk.pk.Set(public)

	return &pk
}

// Point returns a reference to the edwards25519.Point representing the public key.
func (pk *PublicKey) Point() *edwards25519.Point {
	return &pk.pk
}

// Equal returns true if the public key is equal to pk0
func (pk *PublicKey) Equal(pkOther *PublicKey) bool {
	return pk.pk.Equal(&pkOther.pk) == 1
}

// ToEd25519 converts the PublicKey to an ed25519 compatible format
func (pk *PublicKey) ToEd25519() ed25519.PublicKey {
	var key [32]byte
	copy(key[:], pk.pk.Bytes())
	return key[:]
}

func newPublicKey(key ed25519.PublicKey) (*PublicKey, error) {
	var pk PublicKey
	if _, err := pk.pk.SetBytes(key); err != nil {
		return nil, err
	}
	return &pk, nil
}

func newKeyPair(key ed25519.PrivateKey) (*edwards25519.Scalar, *PublicKey) {
	var (
		sk edwards25519.Scalar
		pk PublicKey
	)
	digest := sha512.Sum512(key[:32])

	sk.SetBytesWithClamping(digest[:32])
	pk.pk.ScalarBaseMult(&sk)

	return &sk, &pk
}
