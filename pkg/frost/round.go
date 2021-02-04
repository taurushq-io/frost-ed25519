package frost

import "github.com/taurusgroup/tg-tss/pkg/frost/messages"

type Round interface {
	StoreMessage(message *messages.Message) error
	CanProcess() bool
	ProcessRound() ([]*messages.Message, error)
	NextRound() Round
	Reset()
}
