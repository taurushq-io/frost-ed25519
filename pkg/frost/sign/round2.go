package sign

import (
	"errors"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/frost/messages"
)

var ErrValidateSigShare = errors.New("failed to validate sig share")

type round2 struct {
	*round1
}

func (round *round2) CanProcess() bool {
	if len(round.msgs2) == len(round.AllParties)-1 {
		for id := range round.Parties {
			if id == round.PartySelf {
				continue
			}
			if _, ok := round.msgs2[id]; !ok {
				return false
			}
		}
	}
	return true
}

func (round *round2) ProcessRound() ([]*messages.Message, error) {
	var sig edwards25519.Scalar
	var RPrime, ANeg edwards25519.Point

	sig.Set(edwards25519.NewScalar())

	for id, party := range round.Parties {
		if id != round.PartySelf {
			party.Zi.Set(&round.msgs2[id].Zi)
		}

		l := frost.ComputeLagrange(id, round.AllParties)
		l.Multiply(l, &round.C) // 𝛌 * c
		// R' = [𝛌 * c][-1] Y + [z] B
		//    = [z - s*𝛌 * c] B
		ANeg.Negate(&party.Public)
		RPrime.VarTimeDoubleScalarBaseMult(l, &ANeg, &party.Zi)
		if RPrime.Equal(&party.Ri) != 1 {
			return nil, fmt.Errorf("party %d: %w", id, ErrValidateSigShare)
		}

		sig.Add(&sig, &party.Zi)
	}

	ANeg.Negate(round.Y.Point())
	RPrime.VarTimeDoubleScalarBaseMult(&round.C, &ANeg, &sig)
	if RPrime.Equal(&round.R) != 1 {
		return nil, fmt.Errorf("party %d: %w", round.PartySelf, ErrValidateSigShare)
	}

	msg := messages.NewSign3(&round.R, &sig)
	return []*messages.Message{msg}, nil
}

func (round *round2) NextRound() frost.Round {
	return round
}
