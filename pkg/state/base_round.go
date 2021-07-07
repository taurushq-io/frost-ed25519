package state

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type BaseRound struct {
	selfID   party.ID
	partyIDs party.IDSlice
}

func NewBaseRound(selfID party.ID, partyIDs party.IDSlice) (*BaseRound, error) {
	if !partyIDs.Contains(selfID) {
		return nil, errors.New("PartyIDs should contain selfID")
	}
	return &BaseRound{
		selfID:   selfID,
		partyIDs: partyIDs,
	}, nil
}

func (r *BaseRound) ProcessMessage(*messages.Message) *Error {
	return nil
}

func (r BaseRound) SelfID() party.ID {
	return r.selfID
}

func (r BaseRound) PartyIDs() party.IDSlice {
	return r.partyIDs
}
