package sign

import (
	"errors"

	"filippo.io/edwards25519"
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
		err := rounds.NewError(id, ErrValidateSigShare)
		round.Output.Abort(err)
		return err
	}
	party.Zi.Set(&msg.Sign2.Zi)
	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	var S edwards25519.Scalar

	// S = ∑ s_i
	S.Set(edwards25519.NewScalar())
	for _, party := range round.Parties {
		// s += s_i
		S.Add(&S, &party.Zi)
	}

	Signature := &eddsa.Signature{
		R: round.R,
		S: S,
	}

	// Verify the full signature here too.
	if !Signature.Verify(round.Message, round.GroupKey) {
		err := rounds.NewError(0, ErrValidateSignature)
		round.Output.Abort(err)
		return nil, err
	}

	round.Output.Signature = Signature
	round.Output.Abort(nil)
	return nil, nil
}

func (round *round2) NextRound() rounds.Round {
	return nil
}
