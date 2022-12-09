package hub

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type BaseHubRound struct {
	selfID   party.ID
	partyIDs party.IDSlice
}

func NewBaseHubRound(selfID party.ID, partyIDs party.IDSlice) (*BaseHubRound, error) {
	if !partyIDs.Contains(selfID) {
		return nil, errors.New("PartyIDs should contain selfID")
	}
	return &BaseHubRound{
		selfID:   selfID,
		partyIDs: partyIDs,
	}, nil
}

func (r *BaseHubRound) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (r BaseHubRound) SelfID() party.ID {
	return r.selfID
}

func (r BaseHubRound) PartyIDs() party.IDSlice {
	return r.partyIDs
}
