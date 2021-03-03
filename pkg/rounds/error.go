package rounds

import (
	"fmt"
)

type Error struct {
	PartyID     uint32
	RoundNumber int
	err         error
}

func NewError(partyID uint32, err error) *Error {
	return &Error{
		PartyID: partyID,
		err:     err,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("party %d: round %d: %s", e.PartyID, e.RoundNumber, e.err.Error())
}
