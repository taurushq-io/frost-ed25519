package sign

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/frost"
)

type round1 struct {
	*round0
}

func (r *round1) CanProcess() bool {
	if len(r.msgs1) == len(r.AllParties)-1 {
		for id := range r.Parties {
			if _, ok := r.msgs1[id]; !ok {

				r.canProceed = false

				return false
			}
		}
	}
	return true
}

func (r *round1) ProcessRound() ([][]byte, error) {
	if r.canProceed {
		return nil, ErrRoundProcessed
	}
	var err error

	partyCount := len(r.AllParties)

	// We allocate a new buffer which contains a sorted list of triples (i, B_i, E_i) for each party i
	buf := make([]byte, 0, partyCount * (4 + 32 + 32))
	B := bytes.NewBuffer(buf)

	for _, id := range r.AllParties {
		party := r.Parties[id]
		party.CommitmentD, err = new(edwards25519.Point).SetBytes(r.msgs1[id].CommitmentD)
		if err != nil {
			return nil, err
		}
		party.CommitmentE, err = new(edwards25519.Point).SetBytes(r.msgs1[id].CommitmentE)
		if err != nil {
			return nil, err
		}

		binary.Write(B, binary.BigEndian, id)

		B.Write(r.msgs1[id].CommitmentD)
		B.Write(r.msgs1[id].CommitmentE)
	}

	R := edwards25519.NewIdentityPoint()

	// DIFFERENT_TO_ISIS we actually follow the paper here since we can't easily clone the state of a hash
	h := sha512.New()
	for id, party := range r.Parties {
		h.Reset()

		// Domain seperation
		h.Write([]byte("FROST-SHA512"))

		// Write ID
		binary.Write(h, binary.BigEndian, id)

		// Write Message
		h.Write(r.Message)

		// Write list B
		B.WriteTo(h)


		h.Write(r.Message)

		party.Rho = new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))

		party.R = new(edwards25519.Point).ScalarMult(party.Rho, party.CommitmentE)
		party.R.Add(party.R, party.CommitmentD)

		R.Add(R, party.R)
	}

	r.R = R

	c := frost.ComputeChallenge(r.Message, r.GroupKey, R)
	r.Commitment = c


	lagrange, err := frost.ComputeLagrange(r.PartySelf, r.AllParties)
	if err != nil {
		return nil, fmt.Errorf("failed to compute own Lagrange: %w", err)
	}

	sigShare := edwards25519.NewScalar()
	sigShare.Multiply(lagrange, r.Secret.Secret)
	sigShare.Multiply(sigShare, c) // lambda * s * c

	eRho := edwards25519.NewScalar()
	eRho.Multiply(r.e, r.Parties[r.PartySelf].Rho) // e * rho

	sigShare.Add(sigShare, eRho) // e * rho + lambda * s * c
	sigShare.Add(sigShare, r.d)

	r.Parties[r.PartySelf].SigShare = sigShare

	zero := edwards25519.NewScalar()
	r.e.Set(zero)
	r.d.Set(zero)



	msg := make([]byte, 0, 4 + 1 + 32)
	binary.BigEndian.PutUint32(msg, r.PartySelf)
	msg = append(msg, byte(MessageTypeSign2))
	msg = append(msg, sigShare.Bytes()...)

	r.canProceed = true
	return [][]byte{msg}, nil
	//msg := &Message{
	//	From:   r.PartySelf,
	//	Sign:   &Message{
	//		Msg2: &Msg2{SignatureShare: sigShare.Bytes()},
	//	},
	//}
	//r.canProceed = true
	//return []*Message{msg}, nil

}