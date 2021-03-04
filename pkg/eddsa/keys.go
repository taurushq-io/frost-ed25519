package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// PrivateKey represents a FROST-Ed25519 signing key.
// It contains a reference to PublicKey.
type PrivateKey struct {
	sk edwards25519.Scalar
	pk *PublicKey
}

// PublicKey represents a FROST-Ed25519 verification key.
type PublicKey struct {
	pk edwards25519.Point
}

func NewPrivateKeyFromScalar(secret *edwards25519.Scalar) *PrivateKey {
	var (
		sk PrivateKey
		pk PublicKey
	)
	pk.pk.ScalarBaseMult(secret)
	sk.pk = &pk
	sk.sk.Set(secret)
	return &sk
}

func NewPublicKeyFromPoint(public *edwards25519.Point) *PublicKey {
	var pk PublicKey

	pk.pk.Set(public)

	return &pk
}

func newPublicKey(key ed25519.PublicKey) (*PublicKey, error) {
	var pk PublicKey
	if _, err := pk.pk.SetBytes(key); err != nil {
		return nil, err
	}
	return &pk, nil
}

func newKeyPair(key ed25519.PrivateKey) (*PrivateKey, *PublicKey) {
	var (
		sk PrivateKey
		pk PublicKey
	)
	digest := sha512.Sum512(key[:32])

	sk.sk.SetBytesWithClamping(digest[:32])
	pk.pk.ScalarBaseMult(&sk.sk)
	sk.pk = &pk

	return &sk, &pk
}

// ToEdDSA converts the PublicKey to an ed25519 compatible format
func (pk *PublicKey) ToEdDSA() ed25519.PublicKey {
	var key [32]byte
	copy(key[:], pk.pk.Bytes())
	return key[:]
}

// PublicKey returns the associated public key.
func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}

// Scalar returns a reference to the edwards25519.Scalar representing the private key.
func (sk *PrivateKey) Scalar() *edwards25519.Scalar {
	return &sk.sk
}

// Point returns a reference to the edwards25519.Point representing the public key.
func (pk *PublicKey) Point() *edwards25519.Point {
	return &pk.pk
}

// Equal returns true if the public key is equal to pk0
func (pk *PublicKey) Equal(pkOther *PublicKey) bool {
	return pk.pk.Equal(&pkOther.pk) == 1
}
