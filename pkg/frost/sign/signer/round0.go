package signer

import (
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *round0) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (round *Round0Signer) GenerateMessages() ([]*messages.Message, *state.Error) {
	selfParty := round.Parties[round.SelfID()]

	// Sample dᵢ, Dᵢ = [dᵢ] B
	scalar.SetScalarRandom(&round.d)
	selfParty.Di.ScalarBaseMult(&round.d)

	// Sample eᵢ, Dᵢ = [eᵢ] B
	scalar.SetScalarRandom(&round.e)
	selfParty.Ei.ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.SelfID(), &selfParty.Di, &selfParty.Ei)

	return []*messages.Message{msg}, nil
}

func (round *Round0Signer) NextRound() state.Round {
	return &round1Signer{round}
}
