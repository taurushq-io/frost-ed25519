package sign

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

var hashDomainSeparation = []byte("FROST-SHA512")

func (round *round1) ProcessMessage(msg *messages.Message) *rounds.Error {
	id := msg.From
	identity := edwards25519.NewIdentityPoint()
	if msg.Sign1.Di.Equal(identity) == 1 || msg.Sign1.Ei.Equal(identity) == 1 {
		err := rounds.NewError(id, errors.New("commitment Ei or Di was the identity"))
		round.Output.Abort(err)
		return err
	}
	party := round.Parties[id]
	party.Di.Set(&msg.Sign1.Di)
	party.Ei.Set(&msg.Sign1.Ei)
	return nil
}

func (round *round1) computeRhos() {
	IDBytes := make([]byte, 4)

	// As in the implementation by Isis, we actually compute
	// H ("FROST-SHA512" || Message || B || ID )
	// where
	// B = (ID1 || D_1 || E_1) || (ID_2 || D_2 || E_2) || ... || (ID_N || D_N || E_N) >
	//
	// Start by computing
	// H ("FROST-SHA512" || Message || B)
	B := make([]byte, 0, len(hashDomainSeparation)+len(round.Message)+round.N()*(4+32+32)+4)
	B = append(B, hashDomainSeparation...)
	B = append(B, round.Message...)
	for _, id := range round.AllPartyIDs() {
		party := round.Parties[id]
		binary.BigEndian.PutUint32(IDBytes, id)
		B = append(B, IDBytes...)
		B = append(B, party.Di.Bytes()...)
		B = append(B, party.Ei.Bytes()...)
	}

	// We are going to overwrite the last 4 bytes which contain the ID at every iteration
	offset := len(B)

	for id, party := range round.Parties {
		// Update the last four bytes with the ID
		binary.BigEndian.PutUint32(IDBytes, id)
		copy(B[offset:offset+4], IDBytes)

		// Pi = ρ = H ("FROST-SHA512" || Message || B || ID )
		digest := sha512.Sum512(B)
		party.Pi.SetUniformBytes(digest[:])
	}
}

func (round *round1) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	round.computeRhos()

	round.R.Set(edwards25519.NewIdentityPoint())
	for _, party := range round.Parties {
		// TODO Find a way to do this faster
		// Since all values are public, we don't need to this in constant time
		// Ri = D + [ρ] E
		party.Ri.ScalarMult(&party.Pi, &party.Ei)
		party.Ri.Add(&party.Ri, &party.Di)

		// R += Ri
		round.R.Add(&round.R, &party.Ri)
	}

	// c = H(R, GroupKey, M)
	round.C.Set(eddsa.ComputeChallenge(&round.R, round.GroupKey, round.Message))

	selfID := round.SelfID()
	selfParty := round.Parties[selfID]

	var z edwards25519.Scalar
	// Compute z = d + (e • ρ) + 𝛌 • s • c
	// Note: since we multiply the secret by the Lagrange coefficient,
	// can ignore 𝛌
	z.Multiply(&round.SecretKeyShare, &round.C) // 𝛌 • s • c
	z.MultiplyAdd(&round.e, &selfParty.Pi, &z)  // (e • ρ) + 𝛌 • s • c
	z.Add(&z, &round.d)                         // d + (e • ρ) + 𝛌 • s • c
	selfParty.Zi.Set(&z)

	msg := messages.NewSign2(selfID, &round.Parties[selfID].Zi)

	return []*messages.Message{msg}, nil
}

func (round *round1) NextRound() rounds.Round {
	return &round2{round}
}
