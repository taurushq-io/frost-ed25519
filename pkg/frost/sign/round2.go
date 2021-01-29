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

	lhs := new(edwards25519.Point)
	rhs := new(edwards25519.Point)

	for _, id := range r.AllParties {
		party := r.Parties[id]
		if id != r.PartySelf {
			party.SigShare = r.msgs2[id].SignatureShare
		}

		lagrange, err := frost.ComputeLagrange(id, r.AllParties)
		if err != nil {
			return nil, err
		}

		lagrange.Multiply(lagrange, r.Commitment)

		lhs.ScalarBaseMult(party.SigShare)
		rhs.ScalarMult(lagrange, party.Public)
		rhs.Add(rhs, party.R)

		if lhs.Equal(rhs) != 1 {
			return nil, fmt.Errorf("party %d: %w", id, ErrValidateSigShare)
		}

		sig.Add(sig, party.SigShare)
	}

	sigFull := &Signature{
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
