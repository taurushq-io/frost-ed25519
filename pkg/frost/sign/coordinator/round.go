package coordinator

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type ProtocolVersion int

const (
	FROST_1 ProtocolVersion = iota
	FROST_2
)

type (
	Round0Coordinator struct {
		*types.FrostRound
		// Parties maps IDs to a struct containing all intermediary data for each signer.
		Parties map[party.ID]*types.Signer

		// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
		GroupKey eddsa.PublicKey
	}
	Round1Coordinator struct {
		*Round0Coordinator
	}

	Round2Coordinator struct {
		*Round0Coordinator
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
