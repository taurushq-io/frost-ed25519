package sign

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
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
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return nil, frost.ErrRoundProcessed
	}

	var sig edwards25519.Scalar
	var RPrime, ANeg edwards25519.Point

	// sig = s = ∑ s_i
	sig.Set(edwards25519.NewScalar())

	for id, party := range round.Parties {
		if id != round.PartySelf {
			party.Zi.Set(&round.msgs2[id].Zi)
		}

		// We have already multiplied the public key by the lagrange coefficient,
		// so we we simply check
		//
		// 	R' =  [-c] Y + [z] B = [-c * 𝛌] [x] B + [z] B
		//     =  [-c * 𝛌 * x + z] B
		//  R =? R'
		//
		ANeg.Negate(&party.Public)
		RPrime.VarTimeDoubleScalarBaseMult(&round.C, &ANeg, &party.Zi)
		if RPrime.Equal(&party.Ri) != 1 {
			return nil, fmt.Errorf("party %d: %w", id, ErrValidateSigShare)
		}

		// s += s_i
		sig.Add(&sig, &party.Zi)
	}

	// Verify the full signature here too.
	ANeg.Negate(&round.Y)
	RPrime.VarTimeDoubleScalarBaseMult(&round.C, &ANeg, &sig)
	if RPrime.Equal(&round.R) != 1 {
		return nil, fmt.Errorf("party %d: %w", round.PartySelf, ErrValidateSigShare)
	}

	msg := messages.NewSignOutput(&round.R, &sig)
	round.readyForNextRound = true
	return []*messages.Message{msg}, nil
}

func (round *round2) NextRound() frost.Round {
	return round
}
