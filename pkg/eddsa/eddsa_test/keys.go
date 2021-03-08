package eddsa_test

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
)

func GenerateSecrets(set *party.Set, threshold party.Size) (*edwards25519.Scalar, map[party.ID]*eddsa.SecretShare) {
	if threshold >= set.N() {
		panic("threshold must be at most the size of set minus 1")
	}
	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(threshold, secret)
	shares := make(map[party.ID]*eddsa.SecretShare, set.N())
	for id := range set.Range() {
		shares[id] = eddsa.NewSecretShare(id, poly.Evaluate(id.Scalar()))
	}
	return secret, shares
}

func GeneratePublic(threshold party.Size, secretShares map[party.ID]*eddsa.SecretShare) *eddsa.Public {
	publicShares := make(map[party.ID]*edwards25519.Point, len(secretShares))
	for id, secret := range secretShares {
		var pk edwards25519.Point
		publicShares[id] = pk.ScalarBaseMult(secret.Scalar())
	}
	return eddsa.NewPublic(publicShares, threshold, nil)
}
