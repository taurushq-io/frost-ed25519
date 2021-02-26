package sign

import (
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

const hashDomainSeparation = "FROST-SHA512"

func (round *round1) ProcessMessages() {
	if !round.CanProcessMessages() {
		return
	}
	defer round.NextStep()

	identity := edwards25519.NewIdentityPoint()

	for id, msg := range round.Messages() {
		if id == round.ID() {
			continue
		}

		if msg.Sign1.Di.Equal(identity) == 1 ||
			msg.Sign1.Ei.Equal(identity) == 1 {
			round.Abort(id, errors.New("commitment Ei or Di was the identity"))
		}

		party := round.Parties[id]
		party.Di.Set(&msg.Sign1.Di)
		party.Ei.Set(&msg.Sign1.Ei)
	}
}

func (round *round1) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()

	// As in the implementation by Isis, we actually compute
	// H ("FROST-SHA512" || Message || B || ID )
	// where
	// B = (ID1 || D_1 || E_1) || (ID_2 || D_2 || E_2) || ... || (ID_N || D_N || E_N) >
	//
	// Start by computing
	// H ("FROST-SHA512" || Message || B)
	h := sha512.New()
	_, _ = h.Write([]byte(hashDomainSeparation))
	_, _ = h.Write(round.Message)
	for _, id := range round.AllPartyIDs {
		party := round.Parties[id]

		// H ( ... || ID || Di || Ei )
		_ = binary.Write(h, binary.BigEndian, id)
		_, _ = h.Write(party.Di.Bytes())
		_, _ = h.Write(party.Ei.Bytes())
	}

	// Save the state of the hash function
	hashState, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(fmt.Errorf("failed to save hash function state: %w", err))
	}

	round.R.Set(edwards25519.NewIdentityPoint())
	for id, party := range round.Parties {
		// Reset the hash to
		// H ("FROST-SHA512" || Message || B)
		if h.(encoding.BinaryUnmarshaler).UnmarshalBinary(hashState) != nil {
			panic(fmt.Errorf("failed to restore hash function state: %w", err))
		}

		// Add the ID at the end and compute
		// H ("FROST-SHA512" || Message || B || ID )
		_ = binary.Write(h, binary.BigEndian, id)

		// Pi = ρ = H ("FROST-SHA512" || Message || B || ID )
		party.Pi.SetUniformBytes(h.Sum(nil))

		// Ri = D + [ρ] E
		party.Ri.ScalarMult(&party.Pi, &party.Ei)
		party.Ri.Add(&party.Ri, &party.Di)

		// R += Ri
		round.R.Add(&round.R, &party.Ri)
	}

	// c = H(R, GroupKey, M)
	round.C.Set(eddsa.ComputeChallenge(&round.R, &round.GroupKey, round.Message))

	// Compute z = d + (e • ρ) + 𝛌 • s • c
	{
		var z edwards25519.Scalar
		selfParty := round.Parties[round.ID()]

		// z = d + (e • ρ) + 𝛌 • s • c
		// Note: since we multiply the secret by the Lagrange coefficient,
		// can ignore 𝛌
		z.Multiply(&round.SecretKeyShare, &round.C) // 𝛌 • s • c
		z.MultiplyAdd(&round.e, &selfParty.Pi, &z)  // (e • ρ) + 𝛌 • s • c
		z.Add(&z, &round.d)                         // d + (e • ρ) + 𝛌 • s • c

		selfParty.Zi.Set(&z)
	}
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
