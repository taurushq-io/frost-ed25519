package state

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

// Error represents an error related to the protocol execution, and requires an abort.
// If PartyID is 0, then it was not possible to attribute the fault to one particular party.
type Error struct {
	PartyID     party.ID
	RoundNumber int
	err         error
}

// NewError wraps err in an Error and attaches the culprit's ID
func NewError(partyID party.ID, err error) *Error {
	return &Error{
		PartyID: partyID,
		err:     err,
	}
}

// Error implement error
func (e Error) Error() string {
	return fmt.Sprintf("party %d: round %d: %s", e.PartyID, e.RoundNumber, e.err.Error())
}
