package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

type (
	PrivateKey struct {
		sk edwards25519.Scalar
		pk *PublicKey
	}
	PublicKey struct {
		pk edwards25519.Point
	}
	PublicKeyShares map[uint32]*PublicKey
)

func NewKeyPair(key ed25519.PrivateKey) (*PrivateKey, *PublicKey) {
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

func NewPrivateKeyFromScalar(secret *edwards25519.Scalar, public *PublicKey) *PrivateKey {
	var sk PrivateKey
	if public == nil {
		var pk PublicKey
		pk.pk.ScalarBaseMult(secret)
		public = &pk
	}
	sk.pk = public
	sk.sk.Set(secret)
	return &sk
}

func NewPublicKeyFromPoint(public *edwards25519.Point) *PublicKey {
	var pk PublicKey

	pk.pk.Set(public)

	return &pk
}

func NewPublicKey(key ed25519.PublicKey) (*PublicKey, error) {
	var (
		err error
		pk  PublicKey
	)
	_, err = pk.pk.SetBytes(key)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

func (pk *PublicKey) ToEdDSA() ed25519.PublicKey {
	var key [32]byte
	copy(key[:], pk.pk.Bytes())
	return key[:]
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}

func (sk *PrivateKey) Scalar() *edwards25519.Scalar {
	var s edwards25519.Scalar
	return s.Set(&sk.sk)
}

func (pk *PublicKey) Point() *edwards25519.Point {
	var p edwards25519.Point
	return p.Set(&pk.pk)
}

func (pk *PublicKey) Equal(pk0 *PublicKey) bool {
	return pk.pk.Equal(&pk0.pk) == 1
}
