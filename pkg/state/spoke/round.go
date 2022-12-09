package spoke

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type SpokeRound interface {
	state.Round

	// The following methods are implemented in BaseRound and can therefore be
	// be inherited by the Round0 struct.

	// SelfID returns the ID of the round hub
	HubID() party.ID
}
