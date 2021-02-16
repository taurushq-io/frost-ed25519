package sign

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round1) ProcessMessages() {
	if !round.CanProcessMessages() {
		return
	}
	defer round.NextStep()

	for id, msg := range round.Messages() {
		if id == round.ID() {
			continue
		}
		party := round.Parties[id]
		party.Di.Set(&msg.Sign1.Di)
		party.Ei.Set(&msg.Sign1.Ei)
	}
	return
}

func (round *round1) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()

	var IDBuffer [4]byte

	// B = (ID1 || D_1 || E_1) || (ID_2 || D_2 || E_2) || ... || (ID_N || D_N || E_N) >
	var B []byte
	{
		// We allocate a new buffer which contains a sorted list of triples (i, B_i, E_i) for each party i
		buffer := bytes.NewBuffer(make([]byte, 0, round.N()*(4+32+32)))
		for _, id := range round.AllPartyIDs {
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

	// c = H(R, GroupKey, M)
	c := eddsa.ComputeChallenge(round.Message, &round.GroupKey, &round.R)
	round.C.Set(c)

	// Compute z = d + (e • ρ) + 𝛌 • s • c
	{
		var z edwards25519.Scalar
		selfParty := round.Parties[round.ID()]

		// z = d + (e • ρ) + 𝛌 • s • c
		// Note: since we multiply the secret by the Lagrange coefficient,
		// can ignore 𝛌
		z.Multiply(&round.SecretKeyShare, c)       // 𝛌 • s • c
		z.MultiplyAdd(&round.e, &selfParty.Pi, &z) // (e • ρ) + 𝛌 • s • c
		z.Add(&z, &round.d)                        // d + (e • ρ) + 𝛌 • s • c

		selfParty.Zi.Set(&z)
	}

	return
}

func (round *round1) GenerateMessages() []*messages.Message {
	if !round.CanGenerateMessages() {
		return nil
	}
	defer round.NextStep()

	msg := messages.NewSign2(round.ID(), &round.Parties[round.ID()].Zi)

	return []*messages.Message{msg}
}

func (round *round1) NextRound() rounds.Round {
	if round.PrepareNextRound() {
		return &round2{round}
	}
	return round
}
