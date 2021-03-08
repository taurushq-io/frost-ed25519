package main

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
)

var MESSAGE = []byte("Hello Everybody")

func setupParties(t, n party.Size) (partySet, signSet *party.Set, secretShares map[party.ID]*eddsa.SecretShare, publicShares *eddsa.Shares) {
	var err error
	partySet = helpers.GenerateSet(n)
	_, secretShares = helpers.GenerateSecrets(partySet, t)
	publicShares = helpers.GenerateShares(t, secretShares)
	signIDs := partySet.Take(n + 1)
	signSet, err = party.NewSet(signIDs)
	if err != nil {
		panic(err)
	}
	return
}
