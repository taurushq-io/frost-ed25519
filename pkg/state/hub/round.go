package hub

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type HubRound interface {
	state.Round

	// PartyIDs returns a set containing all parties participating in the round
	PartyIDs() party.IDSlice
}
