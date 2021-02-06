package frost

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
)

var (
	ErrMessageNotForSelf = errors.New("message is not addressed to us")
	ErrNoSignContent     = errors.New("message does not contain sign content")
	ErrInvalidSender     = errors.New("message sender is not in set of signers")
	ErrDuplicateMessage  = errors.New("message already received from party")
	ErrMessageStore      = errors.New("could not find message to store")
	ErrRoundProcessed    = errors.New("round was already processed")
)

type Round interface {
	// A Round represents the state of protocol from the perspective of the party.
	//

	//
	StoreMessage(message *messages.Message) error

	//
	CanProcess() bool

	// Pro
	ProcessRound() ([]*messages.Message, error)

	// NextRound will return the next round that is possible at the time.
	// If it is not possible to advance to the next round, then the current one is returned.
	NextRound() Round

	// Reset erases all temporary data.
	Reset()

	// ID of the signer.
	ID() uint32
}
