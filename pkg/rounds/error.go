package rounds

type Error struct {
	partyID     uint32
	roundNumber int
	err         error
}

func NewError(partyID uint32, err error) *Error {
	return &Error{
		partyID: partyID,
		err:     err,
	}
}

func (e *Error) Error() string {
	return e.err.Error()
}
