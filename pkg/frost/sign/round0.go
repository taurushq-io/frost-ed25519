package sign

import (
	"crypto/rand"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round0) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()

	var buf [64]byte
	party := round.Parties[round.ID()]

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
}

func (round *round0) GenerateMessages() []*messages.Message {
	if !round.CanGenerateMessages() {
		return nil
	}
	defer round.NextStep()

	party := round.Parties[round.ID()]
	msg := messages.NewSign1(round.ID(), &party.Di, &party.Ei)

	return []*messages.Message{msg}
}

func (round *round0) NextRound() rounds.Round {
	if round.PrepareNextRound() {
		return &round1{round}
	}
	return round
}
