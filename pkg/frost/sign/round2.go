package sign

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

var (
	ErrValidateSigShare  = errors.New("signature share is invalid")
	ErrValidateSignature = errors.New("full signature is invalid")
)

func (round *round2) ProcessMessage(msg *messages.Message) *state.Error {
	id := msg.From
	otherParty := round.Parties[id]

	var publicNeg, RPrime ristretto.Element
	publicNeg.Negate(&otherParty.Public)

	// RPrime = [c](-A) + [s]B
	RPrime.VarTimeDoubleScalarBaseMult(&round.C, &publicNeg, &msg.Sign2.Zi)
	if RPrime.Equal(&otherParty.Ri) != 1 {
		return state.NewError(id, ErrValidateSigShare)
	}
	otherParty.Zi.Set(&msg.Sign2.Zi)
	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *state.Error) {
	// S = ∑ sᵢ
	S := ristretto.NewScalar()
	for _, otherParty := range round.Parties {
		// s += sᵢ
		S.Add(S, &otherParty.Zi)
	}

	sig := &eddsa.Signature{
		R: round.R,
		S: *S,
	}

	if !round.GroupKey.Verify(round.Message, sig) {
		return nil, state.NewError(0, ErrValidateSignature)
	}

	round.Output.Signature = sig

	return nil, nil
}

func (round *round2) NextRound() state.Round {
	return nil
}
