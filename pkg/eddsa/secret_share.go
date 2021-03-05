package eddsa

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

// SecretShare is the share
type SecretShare struct {
	ID party.ID
	sk edwards25519.Scalar
}

func NewSecretShare(id party.ID, secret *edwards25519.Scalar) *SecretShare {
	var share SecretShare
	share.ID = id
	share.sk.Set(secret)
	return &share
}

// Scalar returns a reference to the edwards25519.Scalar representing the private key.
func (sk *SecretShare) Scalar() *edwards25519.Scalar {
	return &sk.sk
}

// PublicKey returns a reference to the edwards25519.Scalar representing the private key.
func (sk *SecretShare) PublicKey() *PublicKey {
	var pk PublicKey
	pk.pk.ScalarBaseMult(&sk.sk)
	return &pk
}
