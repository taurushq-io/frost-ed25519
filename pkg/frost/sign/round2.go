package sign

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

var (
	ErrValidateSigShare  = errors.New("signature share is invalid")
	ErrValidateSignature = errors.New("full signature is invalid")
)

func (round *round2) ProcessMessage(msg *messages.Message) *rounds.Error {
	id := msg.From
	party := round.Parties[id]
	if !eddsa.Verify(&round.C, &msg.Sign2.Zi, party.Public, &party.Ri) {
		return rounds.NewError(id, ErrValidateSigShare)
	}
	party.Zi.Set(&msg.Sign2.Zi)
	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	var Signature eddsa.Signature

	// S = ∑ s_i
	S := &Signature.S
	for _, party := range round.Parties {
		// s += s_i
		S.Add(S, &party.Zi)
	}

	Signature.R.Set(&round.R)

	// Verify the full signature here too.
	if !Signature.Verify(round.Message, round.GroupKey) {
		return nil, rounds.NewError(0, ErrValidateSignature)
	}

	round.Output.Signature = &Signature
	return nil, nil
}

func (round *round2) NextRound() rounds.Round {
	return nil
}
