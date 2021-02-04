package sign

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"

	//"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

func generateFakeParties(t, n uint32) (*edwards25519.Scalar, []uint32, map[uint32]*frost.Party, map[uint32]*frost.PartySecret) {
	allParties := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i + 1
	}

	secret := common.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)
	shares := poly.EvaluateMultiple(allParties)

	secrets := map[uint32]*frost.PartySecret{}
	parties := map[uint32]*frost.Party{}
	for _, id := range allParties {
		secrets[id] = &frost.PartySecret{
			Index:  id,
			Secret: *shares[id],
		}
		parties[id] = &frost.Party{
			Index:  id,
			Public: *edwards25519.NewIdentityPoint().ScalarBaseMult(shares[id]),
		}
	}

	return secret, allParties, parties, secrets
}

func generateFakePartiesAdditive(t, n uint32) (*edwards25519.Scalar, []uint32, map[uint32]*frost.Party, map[uint32]*frost.PartySecret) {
	allParties := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i
	}

	secrets := map[uint32]*frost.PartySecret{}
	parties := map[uint32]*frost.Party{}
	fullSecret := edwards25519.NewScalar()
	for _, id := range allParties {
		secret := common.NewScalarRandom()
		fullSecret.Add(fullSecret, secret)
		secrets[id] = &frost.PartySecret{
			Index:  id,
			Secret: *secret,
		}
		parties[id] = &frost.Party{
			Index:  id,
			Public: *edwards25519.NewIdentityPoint().ScalarBaseMult(secret),
		}
	}

	return fullSecret, allParties, parties, secrets
}
