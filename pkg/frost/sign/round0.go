package sign

import (
	"crypto/rand"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round0) ProcessMessage(msg *messages.Message) *rounds.Error {
	return nil
}

func (round *round0) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	var buf [64]byte
	party := round.Parties[round.SelfID()]

	// Sample d_i, D_i = [d_i] B
	_, err := rand.Read(buf[:])
	if err != nil {
		panic("failed to read")
	}
	round.d.SetUniformBytes(buf[:])
	party.Di.ScalarBaseMult(&round.d)

	// Sample e_i, D_i = [e_i] B
	_, err = rand.Read(buf[:])
	if err != nil {
		panic("failed to read")
	}
	round.e.SetUniformBytes(buf[:])
	party.Ei.ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.SelfID(), &party.Di, &party.Ei)

	return []*messages.Message{msg}, nil
}

func (round *round0) NextRound() rounds.Round {
	return &round1{round}
}
