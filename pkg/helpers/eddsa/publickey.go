package eddsa

import (
	"crypto/ed25519"

	"filippo.io/edwards25519"
)

type PublicKey struct {
	edwards25519.Point
}

func NewPublicKey(key ed25519.PublicKey) (*PublicKey, error) {
	var (
		err error
		pk  PublicKey
	)
	_, err = pk.Point.SetBytes(key)
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
