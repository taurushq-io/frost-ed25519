package spoke

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type BaseSpokeRound struct {
	selfID   party.ID
	hubID    party.ID
	partyIDs party.IDSlice
}

func NewBaseSpokeRound(selfID party.ID, hubID party.ID, partyIDs party.IDSlice) (*BaseSpokeRound, error) {
	if !partyIDs.Contains(selfID) {
		return nil, errors.New("PartyIDs should contain selfID")
	}
	return &BaseSpokeRound{
		selfID:   selfID,
		hubID:    hubID,
		partyIDs: partyIDs,
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

func (r BaseSpokeRound) PartyIDs() party.IDSlice {
	return r.partyIDs
}
