package spoke

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type BaseSpokeRound struct {
	selfID party.ID
	hubID  party.ID
}

func NewBaseSpokeRound(selfID party.ID, hubID party.ID) (*BaseSpokeRound, error) {
	return &BaseSpokeRound{
		selfID: selfID,
		hubID:  hubID,
	}, nil
}

func (r *BaseSpokeRound) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (r BaseSpokeRound) SelfID() party.ID {
	return r.selfID
}

func (r BaseSpokeRound) HubID() party.ID {
	return r.hubID
}
