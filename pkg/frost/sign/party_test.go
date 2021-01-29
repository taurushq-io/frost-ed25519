package sign

import (
	"filippo.io/edwards25519"
	//"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/vss"
)

func generateFakeParties(t, n uint32) (*edwards25519.Scalar, []uint32, map[uint32]*frost.Party, map[uint32]*frost.PartySecret) {
	allParties := make([]uint32, n)
	allPartiesT := make([]common.Party, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i+1
		allPartiesT[i] = common.Party(i+1)
	}

	secret, _ := common.NewScalarRandom()
	_, shares, _ := vss.NewVSS(t, secret, allPartiesT)

	secrets := map[uint32]*frost.PartySecret{}
	parties := map[uint32]*frost.Party{}
	for _, id := range allParties {
		secrets[id] = &frost.PartySecret{
			Index:  id,
			Secret: shares[common.Party(id)],
		}
		parties[id] = &frost.Party{
			Index:  id,
			Public: new(edwards25519.Point).ScalarBaseMult(shares[common.Party(id)]),
		}
	}

	return secret, allParties, parties, secrets
}

func generateFakePartiesAdditive(t, n uint32) (*edwards25519.Scalar, []uint32, map[uint32]*frost.Party, map[uint32]*frost.PartySecret) {
	allParties := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i+1
	}

	secrets := map[uint32]*frost.PartySecret{}
	parties := map[uint32]*frost.Party{}
	fullSecret := edwards25519.NewScalar()
	for _, id := range allParties {
		secret, _ := common.NewScalarRandom()
		fullSecret.Add(fullSecret, secret)
		secrets[id] = &frost.PartySecret{
			Index:  id,
			Secret: secret,
		}
		parties[id] = &frost.Party{
			Index:  id,
			Public: new(edwards25519.Point).ScalarBaseMult(secret),
		}
	}

	return fullSecret, allParties, parties, secrets
}