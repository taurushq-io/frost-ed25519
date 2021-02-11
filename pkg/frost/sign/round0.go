package sign

import (
	"crypto/rand"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
)

func (round *base) ProcessMessages() error {
	round.Lock()
	defer round.Unlock()

	//if round.messagesProcessed {
	//	return nil
	//}

	round.messagesProcessed = true

	return nil
}

func (round *base) ProcessRound() error {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed {
		return frost.ErrRoundProcessed
	}

	var buf [64]byte
	party := round.Parties[round.PartySelf]

	// Sample d_i, D_i = [d_i] B
	rand.Read(buf[:])
	round.d.SetUniformBytes(buf[:])
	party.Di.ScalarBaseMult(&round.d)

	// Sample e_i, D_i = [e_i] B
	rand.Read(buf[:])
	round.e.SetUniformBytes(buf[:])
	party.Ei.ScalarBaseMult(&round.e)

	round.roundProcessed = true

	return nil
}

func (round *base) GenerateMessages() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if !(round.roundProcessed && round.messagesProcessed) {
		return nil, frost.ErrRoundNotProcessed
	}

	party := round.Parties[round.PartySelf]
	msg := messages.NewSign1(round.PartySelf, &party.Di, &party.Ei)

	return []*messages.Message{msg}, nil
}

func (round *base) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed && round.messagesProcessed {
		round.roundProcessed = false
		round.messagesProcessed = false
		return &round1{round}
	}
	return round
}
