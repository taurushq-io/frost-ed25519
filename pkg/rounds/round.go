package rounds

import (
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type Round interface {
	// A Round represents the state of protocol from the perspective of the party.
	//
	// The functions should be called in this given order.

	//  ProcessMessage only runs when all messages for the current Round have been received.
	// It performs any checks and validation necessary, and updates the Round's state.
	ProcessMessage(msg *messages.Message) *Error

	// GenerateMessages returns a slice of messages to be sent out at the end of this Round.
	// If it is not possible for some reason, an empty slice is returned.
	GenerateMessages() ([]*messages.Message, *Error)

	// NextRound will return the next Round that is possible at the time.
	// If it is not possible to advance to the next Round, then the current one is returned.
	NextRound() Round

	AcceptedMessageTypes() []messages.MessageType

	Reset()
}
