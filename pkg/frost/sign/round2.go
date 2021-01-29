package sign

import (
	"encoding/binary"
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
			if _, ok := r.msgs2[id]; !ok {

				r.canProceed = false

				return false
			}
		}
	}
	return true
}

func (r *round2) ProcessRound() ([][]byte, error) {
	if r.canProceed {
		return nil, ErrRoundProcessed
	}

	sig := edwards25519.NewScalar()

	var err error
	lhs := new(edwards25519.Point)
	rhs := new(edwards25519.Point)

	for _, id := range r.AllParties {
		party := r.Parties[id]
		party.SigShare, err = new(edwards25519.Scalar).SetCanonicalBytes(r.msgs2[id].SignatureShare)
		if err != nil {
			return nil, err
		}

		lagrange, err := frost.ComputeLagrange(id, r.AllParties)
		if err != nil {
			return nil, err
		}

		lagrange.Multiply(lagrange, r.Commitment)

		lhs.ScalarBaseMult(party.SigShare)
		rhs.ScalarMult(lagrange, party.Public)
		rhs.Add(rhs, party.R)

		if lhs.Equal(rhs) == 1 {
			return nil, fmt.Errorf("party %d: %w", id, ErrValidateSigShare)
		}

		sig.Add(sig, party.SigShare)
	}

	sigFull := &frost.Signature{
		R: new(edwards25519.Point).Set(r.R),
		S: sig,
	}

	msg := make([]byte, 0, 4 + 1 + 64)
	binary.BigEndian.PutUint32(msg, r.PartySelf)
	msg = append(msg, byte(MessageTypeSignature))
	msg = append(msg, sigFull.Bytes()...)

	r.canProceed = true
	return [][]byte{msg}, nil
	//msg := &Message{
	//	Signature: &frost.Signature{
	//		R: new(edwards25519.Point).Set(r.R),
	//		S: sig,
	//	},
	//}
	//r.canProceed = true
	//return []*Message{msg}, nil
}

