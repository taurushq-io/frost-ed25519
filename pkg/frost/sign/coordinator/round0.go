package coordinator

import (
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *Round0Coordinator) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (round *Round0Coordinator) GenerateMessages() ([]*messages.Message, *state.Error) {
	selfParty := round.Parties[round.FrostRound.BaseRound.SelfID()]

	// Sample dᵢ, Dᵢ = [dᵢ] B
	scalar.SetScalarRandom(&round.d)
	selfParty.Di.ScalarBaseMult(&round.d)

	// Sample eᵢ, Dᵢ = [eᵢ] B
	scalar.SetScalarRandom(&round.e)
	selfParty.Ei.ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.SelfID(), &selfParty.Di, &selfParty.Ei)

	return []*messages.Message{msg}, nil
}

func (round *round0) NextRound() state.Round {
	return &round1{round}
}
