package main

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
)

var MESSAGE = []byte("Hello Everybody")

func setupParties(t, n party.Size) (partyIDs, signIDs party.IDSlice, secretShares map[party.ID]*eddsa.SecretShare, publicShares *eddsa.Public) {
	partyIDs = helpers.GenerateSet(n)
	_, secretShares = helpers.GenerateSecrets(partyIDs, t)
	publicShares = helpers.GeneratePublic(t, secretShares)
	signIDs = partyIDs[:t+1]
	return
}
