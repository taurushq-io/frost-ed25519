package helpers

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func GenerateSecrets(set party.IDSlice, threshold party.Size) (*ristretto.Scalar, map[party.ID]*eddsa.SecretShare) {
	if threshold >= set.N() {
		panic("threshold must be at most the size of set minus 1")
	}
	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(threshold, secret)
	shares := make(map[party.ID]*eddsa.SecretShare, set.N())
	for _, id := range set {
		shares[id] = eddsa.NewSecretShare(id, poly.Evaluate(id.Scalar()))
	}
	return secret, shares
}

func GeneratePublic(threshold party.Size, secretShares map[party.ID]*eddsa.SecretShare) *eddsa.Public {
	publicShares := make(map[party.ID]*ristretto.Element, len(secretShares))
	for id, secret := range secretShares {
		var pk ristretto.Element
		publicShares[id] = pk.ScalarBaseMult(&secret.Secret)
	}
	public, err := eddsa.NewPublic(publicShares, threshold)
	if err != nil {
		panic(err)
	}
	return public
}
