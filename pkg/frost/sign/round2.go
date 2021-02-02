package sign

import (
	"errors"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/frost"
)

var ErrValidateSigShare = errors.New("failed to validate sig share")

type round2 struct {
	*round1
}

func (r *round2) CanProcess() bool {
	if len(r.msgs2) == len(r.AllParties)-1 {
		for id := range r.Parties {
			if id == r.PartySelf {
				continue
			}
			if _, ok := r.msgs2[id]; !ok {
				return false
			}
		}
	}
	return true
}

func (r *round2) ProcessRound() ([][]byte, error) {
	sig := edwards25519.NewScalar()

	RPrime := new(edwards25519.Point)

	for _, id := range r.AllParties {
		party := r.Parties[id]
		if id != r.PartySelf {
			party.SigShare = r.msgs2[id].SignatureShare
		}

		lagrange := frost.ComputeLagrange(id, r.AllParties)

		lagrange.Multiply(lagrange, r.Commitment) // lambda * c
		lagrange.Negate(lagrange)                 // - lambda * c

		// RPrime = [-lambda * c]A + [s] B
		// RPrime = [s - sk*lambda * c]B
		RPrime.VarTimeDoubleScalarBaseMult(lagrange, party.Public, party.SigShare)
		if RPrime.Equal(party.R) != 1 {
			return nil, fmt.Errorf("party %d: %w", id, ErrValidateSigShare)
		}

		sig.Add(sig, party.SigShare)
	}

	sigFull := &frost.Signature{
		R: new(edwards25519.Point).Set(r.R),
		S: sig,
	}

	sigBytes, err := sigFull.Encode(r.PartySelf)
	if err != nil {
		return nil, err
	}
	return [][]byte{sigBytes}, nil
}

func (r *round2) NextRound() frost.Round {
	return r
}
