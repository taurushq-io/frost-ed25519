package rounds

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
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

	// AcceptedMessageTypes should return a slice containing the messages types the protocol accepts.
	// It is constant for all rounds and should therefore be implemented by a "base" round.
	AcceptedMessageTypes() []messages.MessageType

	// Reset is expected to zero out any sensitive data that may have been copied by the round.
	Reset()

	// SelfID returns the ID of the round participant
	SelfID() party.ID

	// Set returns a set containing all parties participating in the round
	Set() *party.Set
}
