package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

type (
	PrivateKey struct {
		edwards25519.Scalar
		pk *PublicKey
	}
	PublicKey struct {
		*edwards25519.Point
	}
)

func NewKeyPair(key ed25519.PrivateKey) (*PrivateKey, *PublicKey) {
	var (
		sk PrivateKey
		pk PublicKey
	)

	digest := sha512.Sum512(key[:32])

	sk.SetBytesWithClamping(digest[:32])

	pk.Point = new(edwards25519.Point).ScalarBaseMult(&sk.Scalar)
	sk.pk = &pk
	return &sk, &pk
}

func NewPublicKey(key ed25519.PublicKey) (*PublicKey, error) {
	var (
		err error
		pk  PublicKey
	)
	pk.Point, err = new(edwards25519.Point).SetBytes(key)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

func (pk *PublicKey) ToEdDSA() ed25519.PublicKey {
	var key [32]byte
	copy(key[:], pk.Bytes())
	return key[:]
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}
