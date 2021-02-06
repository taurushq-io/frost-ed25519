package sign

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

type round1 struct {
	*base
}

func (round *round1) CanProcess() bool {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return false
	}

	if len(round.msgs1) == len(round.AllParties)-1 {
		for id := range round.Parties {
			if id == round.PartySelf {
				continue
			}
			if _, ok := round.msgs1[id]; !ok {
				return false
			}
		}
	}
	return true
}

func (round *round1) ProcessMessages() error {
	for id, party := range round.Parties {
		if id != round.PartySelf {
			party.Di.Set(&round.msgs1[id].Di)
			party.Ei.Set(&round.msgs1[id].Ei)

			delete(round.msgs1, id)
		}
	}

	return nil
}

func (round *round1) ProcessRound() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return nil, frost.ErrRoundProcessed
	}

	if err := round.ProcessMessages(); err != nil {
		return nil, err
	}

	var IDBuffer [4]byte
	partyCount := len(round.AllParties)

	// We allocate a new buffer which contains a sorted list of triples (i, B_i, E_i) for each party i
	buffer := bytes.NewBuffer(make([]byte, 0, partyCount*(4+32+32)))
	for _, id := range round.AllParties {
		party := round.Parties[id]

		binary.BigEndian.PutUint32(IDBuffer[:], id)
		// B || (i || Di || Ei)

		buffer.Write(IDBuffer[:])
		buffer.Write(party.Di.Bytes())
		buffer.Write(party.Ei.Bytes())
	}
	B := buffer.Bytes()

	round.R.Set(edwards25519.NewIdentityPoint())

	// DIFFERENT_TO_ISIS we actually follow the paper here since we can't easily clone the state of a hash
	h := sha512.New()
	for id, party := range round.Parties {
		h.Reset()

		// Domain separation
		h.Write([]byte("FROST-SHA512"))

		// Write ID
		binary.BigEndian.PutUint32(IDBuffer[:], id)
		h.Write(IDBuffer[:])

		// Write Message
		h.Write(round.Message)

		// Write list B
		h.Write(B)

		// Pi = 𝛌 = H(i, M, B)
		party.Pi.SetUniformBytes(h.Sum(nil))

		// Ri = D + [𝛌] E
		party.Ri.ScalarMult(&party.Pi, &party.Ei)
		party.Ri.Add(&party.Ri, &party.Di)

		// Ri += Ri
		round.R.Add(&round.R, &party.Ri)
	}

	var z edwards25519.Scalar

	selfParty := round.Parties[round.PartySelf]

	// c = H(R, Y, M)
	c := eddsa.ComputeChallenge(round.Message, &round.Y, &round.R)

	// z = d + (e • ρ) + 𝛌 • s • c
	z.Multiply(&selfParty.Lagrange, round.Secret) // z = 𝛌 • s
	z.Multiply(&z, c)                             // 𝛌 • s • c
	z.MultiplyAdd(&round.e, &selfParty.Pi, &z)    // (e • ρ) + 𝛌 • s • c
	z.Add(&z, &round.d)                           // d + (e • ρ) + 𝛌 • s • c

	selfParty.Zi.Set(&z)
	round.C.Set(c)

	msg := messages.NewSign2(round.PartySelf, &z)

	round.readyForNextRound = true

	return []*messages.Message{msg}, nil
}
func (round *round1) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		round.readyForNextRound = false
		return &round2{round}
	}
	return round
}
