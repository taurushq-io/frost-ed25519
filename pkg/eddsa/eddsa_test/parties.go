package eddsa_test

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

// NewPartySlice returns n party.ID s in the range [1, ..., n].
func NewPartySlice(n party.Size) []party.ID {
	partyIDs := make([]party.ID, 0, n)
	for i := party.ID(1); i <= n; i++ {
		partyIDs = append(partyIDs, i)
	}
	return partyIDs
}

func GenerateSet(n party.Size) *party.Set {
	set, _ := party.NewSet(NewPartySlice(n))
	return set
}
