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

func (round *round1) ProcessMessages() error {
	round.Lock()
	defer round.Unlock()

	if round.messagesProcessed {
		return nil
	}

	msgs := round.messages.Messages()

	for _, id := range round.AllParties {
		if id == round.PartySelf {
			continue
		}
		party := round.Parties[id]
		party.Di.Set(&msgs[id].Sign1.Di)
		party.Ei.Set(&msgs[id].Sign1.Ei)
	}

	round.messages.NextRound()
	round.messagesProcessed = true

	return nil
}

func (round *round1) ProcessRound() error {
	var IDBuffer [4]byte

	round.Lock()
	defer round.Unlock()

	if round.roundProcessed {
		return frost.ErrRoundProcessed
	}

	partyCount := len(round.AllParties)

	// B = (ID1 || D_1 || E_1) || (ID_2 || D_2 || E_2) || ... || (ID_N || D_N || E_N) >
	var B []byte
	{
		// We allocate a new buffer which contains a sorted list of triples (i, B_i, E_i) for each party i
		buffer := bytes.NewBuffer(make([]byte, 0, partyCount*(4+32+32)))
		for _, id := range round.AllParties {
			party := round.Parties[id]

			binary.BigEndian.PutUint32(IDBuffer[:], id)
			// B = ... || (ID || Di || Ei)

			buffer.Write(IDBuffer[:])
			buffer.Write(party.Di.Bytes())
			buffer.Write(party.Ei.Bytes())
		}
		B = buffer.Bytes()
	}

	round.R.Set(edwards25519.NewIdentityPoint())
	// DIFFERENT_TO_ISIS we actually follow the paper here since we can't easily clone the state of a hash
	h := sha512.New()
	for id, party := range round.Parties {
		h.Reset()

		// H ("FROST-SHA512" || ID || Message || B )
		h.Write([]byte("FROST-SHA512"))
		binary.BigEndian.PutUint32(IDBuffer[:], id)
		h.Write(IDBuffer[:4])
		h.Write(round.Message)
		h.Write(B)

		// Pi = ρ = H(i, M, B)
		party.Pi.SetUniformBytes(h.Sum(nil))

		// Ri = D + [ρ] E
		party.Ri.ScalarMult(&party.Pi, &party.Ei)
		party.Ri.Add(&party.Ri, &party.Di)

		// R += Ri
		round.R.Add(&round.R, &party.Ri)
	}

	// c = H(R, Y, M)
	c := eddsa.ComputeChallenge(round.Message, &round.Y, &round.R)
	round.C.Set(c)

	// Compute z = d + (e • ρ) + 𝛌 • s • c
	{
		var z edwards25519.Scalar
		selfParty := round.Parties[round.PartySelf]

		// z = d + (e • ρ) + 𝛌 • s • c
		z.Multiply(&selfParty.Lagrange, round.Secret) // z = 𝛌 • s
		z.Multiply(&z, c)                             // 𝛌 • s • c
		z.MultiplyAdd(&round.e, &selfParty.Pi, &z)    // (e • ρ) + 𝛌 • s • c
		z.Add(&z, &round.d)                           // d + (e • ρ) + 𝛌 • s • c

		selfParty.Zi.Set(&z)
	}

	round.roundProcessed = true

	return nil
}

func (round *round1) GenerateMessages() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if !(round.roundProcessed && round.messagesProcessed) {
		return nil, frost.ErrRoundNotProcessed
	}

	msg := messages.NewSign2(round.PartySelf, &round.Parties[round.PartySelf].Zi)

	return []*messages.Message{msg}, nil
}

func (round *round1) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed && round.messagesProcessed {
		round.roundProcessed = false
		round.messagesProcessed = false
		return &round2{round}
	}
	return round
}
