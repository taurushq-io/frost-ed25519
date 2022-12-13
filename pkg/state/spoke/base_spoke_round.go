package spoke

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type BaseRound struct {
	selfID   party.ID
	hubID    party.ID
	partyIDs party.IDSlice
}

func NewBaseRound(selfID party.ID, hubID party.ID, partyIDs party.IDSlice) (*BaseRound, error) {
	if !partyIDs.Contains(selfID) {
		return nil, errors.New("PartyIDs should contain selfID")
	}
	return &BaseRound{
		selfID:   selfID,
		hubID:    hubID,
		partyIDs: partyIDs,
	}, nil
}

func (r *BaseRound) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (r BaseRound) SelfID() party.ID {
	return r.selfID
}

func (r BaseRound) HubID() party.ID {
	return r.hubID
}

func (r BaseRound) PartyIDs() party.IDSlice {
	return r.partyIDs
}
