package coordinator

import (
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *Round0Coordinator) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (round *Round0Coordinator) GenerateMessages() ([]*messages.Message, *state.Error) {
	return []*messages.Message{messages.NewPreSignRequest(round.SelfID())}, nil
}

func (round *Round0Coordinator) NextRound() state.Round {
	return &Round1Coordinator{round}
}
