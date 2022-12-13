package state

import (
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type State interface {
	HandleMessage(msg *messages.Message) error

	ProcessAll() []*messages.Message

	WaitForError() error

	IsFinished() bool

	Done() <-chan struct{}

	Err() error
}
