package rounds

import (
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type Round interface {
	// A Round represents the state of protocol from the perspective of the party.
	//
	// The functions should be called in this given order.

	// StoreMessage accepts any unmarshalled message and attempts to store it for later use in the Round
	// It check whether the message is for the right protocol, and whether relevant fields are not nil.
	StoreMessage(message *messages.Message) error

	// ProcessMessages only runs when all messages for the current Round have been received.
	// It performs any checks and validation necessary, and updates the Round's state.
	ProcessMessages()

	// ProcessRound performs all steps necessary to compute outgoing messages.
	// The state is updated, and any subsequent calls will result in an error.
	ProcessRound()

	// GenerateMessages returns a slice of messages to be sent out at the end of this Round.
	// If it is not possible for some reason, an empty slice is returned.
	GenerateMessages() []*messages.Message

	// NextRound will return the next Round that is possible at the time.
	// If it is not possible to advance to the next Round, then the current one is returned.
	NextRound() Round
}

type KeyGenRound interface {
	Round
	WaitForKeygenOutput() (groupKey *eddsa.PublicKey, publicShares *eddsa.Shares, secretKeyShare *eddsa.PrivateKey, err error)
}

type SignRound interface {
	Round
	WaitForSignOutput() (signature *eddsa.Signature, err error)
}
