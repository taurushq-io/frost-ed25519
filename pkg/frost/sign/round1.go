package sign

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/frost/messages"
)

type round1 struct {
	*round0
}

func (r *round1) CanProcess() bool {
	if len(r.msgs1) == len(r.AllParties)-1 {
		for id := range r.Parties {
			if id == r.PartySelf {
				continue
			}
			if _, ok := r.msgs1[id]; !ok {

				return false
			}
		}
	}
	return true
}

func (r *round1) ProcessRound() ([]*messages.Message, error) {
	var IDBuffer [4]byte
	partyCount := len(r.AllParties)

	// We allocate a new buffer which contains a sorted list of triples (i, B_i, E_i) for each party i
	buffer := bytes.NewBuffer(make([]byte, 0, partyCount*(4+32+32)))
	for _, id := range r.AllParties {
		party := r.Parties[id]
		if id != r.PartySelf {
			party.Di.Set(&r.msgs1[id].Di)
			party.Ei.Set(&r.msgs1[id].Ei)
		}
		binary.BigEndian.PutUint32(IDBuffer[:], id)

		// B || (i || Di || Ei)

		buffer.Write(IDBuffer[:])
		buffer.Write(party.Di.Bytes())
		buffer.Write(party.Ei.Bytes())

		// TODO erase Ei, Di message
	}
	B := buffer.Bytes()

	r.R.Set(edwards25519.NewIdentityPoint())

	// DIFFERENT_TO_ISIS we actually follow the paper here since we can't easily clone the state of a hash
	h := sha512.New()
	for id, party := range r.Parties {
		h.Reset()

		// Domain seperation
		h.Write([]byte("FROST-SHA512"))

		// Write ID
		binary.BigEndian.PutUint32(IDBuffer[:], id)
		h.Write(IDBuffer[:])

		// Write Message
		h.Write(r.Message)

		// Write list B
		h.Write(B)

		// Pi = 𝛌 = H(i, M, B)
		party.Pi.SetUniformBytes(h.Sum(nil))

		// Ri = D + [𝛌] E
		party.Ri.Set(edwards25519.NewIdentityPoint()) // TODO needed until the new version of edwards25519
		party.Ri.ScalarMult(&party.Pi, &party.Ei)
		party.Ri.Add(&party.Ri, &party.Di)

		// Ri += Ri
		r.R.Add(&r.R, &party.Ri)
	}

	var l, z edwards25519.Scalar

	selfParty := r.Parties[r.PartySelf]

	// c = H(R, Y, M)
	c := frost.ComputeChallenge(r.Message, r.Y, &r.R)

	// 𝛌
	l.Set(frost.ComputeLagrange(r.PartySelf, r.AllParties))

	// z = d + (e • ρ) + 𝛌 • s • c
	z.Multiply(&l, &r.Secret.Secret)       // z = 𝛌 • s
	z.Multiply(&z, c)                      // 𝛌 • s • c
	z.MultiplyAdd(&r.e, &selfParty.Pi, &z) // (e • ρ) + 𝛌 • s • c
	z.Add(&z, &r.d)                        // d + (e • ρ) + 𝛌 • s • c

	selfParty.Zi.Set(&z)
	r.C.Set(c)

	msg := messages.NewSign2(r.PartySelf, &z)

	return []*messages.Message{msg}, nil
}
func (r *round1) NextRound() frost.Round {
	return &round2{r}
}
