package frost

import "github.com/taurusgroup/frost-ed25519/pkg/messages"

type Communicator interface {
	Send(msg []byte) error
	IncomingChannel(dest uint32) <-chan *messages.Message

	StartKeygen(partyIDs []uint32)
}
