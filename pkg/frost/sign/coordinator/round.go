package coordinator

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state/hub"
)

type ProtocolVersion int

type (
	Round0Coordinator struct {
		*hub.BaseHubRound
		*types.FrostRound
	}
	Round1Coordinator struct {
		*Round0Coordinator
	}

	Round2Coordinator struct {
		*Round1Coordinator
	}
)

func (round *Round0Coordinator) Reset() {
	round.FrostRound.Reset()

	for id, p := range round.Parties {
		p.Reset()
		delete(round.Parties, id)
	}
}

func (round *Round0Coordinator) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{
		messages.MessageTypeNone,
		messages.MessageTypeSign1,
		messages.MessageTypeSign2,
	}
}
