package frost

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

var (
	ErrMessageNotForSelf = errors.New("message is not addressed to us")
	ErrNoSignContent     = errors.New("message does not contain sign content")
	ErrInvalidSender     = errors.New("message sender is not in set of signers")
	ErrDuplicateMessage  = errors.New("message already received from party")
	ErrMessageStore      = errors.New("could not find message to store")
	ErrRoundProcessed    = errors.New("round was already processed")

	ErrMessagesProcessed = errors.New("messages already processed")
	ErrMissingMessage    = errors.New("missing message")
	ErrInvalidMessage    = errors.New("message malformed")
	ErrRoundNotProcessed = errors.New("round is not yet processed")
)

type Round interface {
	// A Round represents the state of protocol from the perspective of the party.
	//
	//

	// StoreMessage accepts any unmarshalled message and attempts to store it for later use in the round
	// It check whether the message is for the right protocol, and whether relevant fields are not nil.
	StoreMessage(message *messages.Message) error

	// CanStart indicates whether we have received all messages for the round,
	// and perform the remaining Round steps.
	CanStart() bool

	// ProcessMessages only runs when all messages for the current round have been received.
	// It performs any checks and validation necessary, and updates the round's state.
	ProcessMessages() error

	// ProcessRound performs all steps necessary to compute outgoing messages.
	// The state is updated, and any subsequent calls will result in an error.
	ProcessRound() error

	// GenerateMessages returns a slice of messages to be sent out at the end of this round.
	//
	GenerateMessages() ([]*messages.Message, error)

	// NextRound will return the next round that is possible at the time.
	// If it is not possible to advance to the next round, then the current one is returned.
	NextRound() Round

	// Reset erases all temporary data.
	// The resulting round cannot be reused.
	Reset()

	// ID of the signer.
	ID() uint32
}

type KeyGenRound interface {
	Round
	WaitForKeyGenOutput() (groupKey *eddsa.PublicKey, groupKeyShares map[uint32]*eddsa.PublicKey, secretKeyShare edwards25519.Scalar, err error)
}

type SignRound interface {
	Round
	WaitForSignOutput() (signature *eddsa.Signature)
}
