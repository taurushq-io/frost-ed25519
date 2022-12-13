package signer

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *Round0Signer) ProcessMessage(msg *messages.Message) *state.Error {
	if msg.Header.From != round.HubID() {
		return state.NewError(msg.Header.From, errors.New("Sign Request not from hub"))
	}
	return nil
}

func (round *Round0Signer) GenerateMessages() ([]*messages.Message, *state.Error) {
	// Sample dᵢ, Dᵢ = [dᵢ] B
	scalar.SetScalarRandom(&round.d)
	D := new(ristretto.Element).ScalarBaseMult(&round.d)

	// Sample eᵢ, Dᵢ = [eᵢ] B
	scalar.SetScalarRandom(&round.e)
	E := new(ristretto.Element).ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.SelfID(), D, E)
	return []*messages.Message{msg}, nil
}

func (round *Round0Signer) NextRound() state.Round {
	return &Round1Signer{round}
}
