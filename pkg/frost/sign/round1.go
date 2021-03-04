package sign

import (
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

var hashDomainSeparation = []byte("FROST-SHA512")

func (round *round1) ProcessMessage(msg *messages.Message) *rounds.Error {
	id := msg.From
	identity := edwards25519.NewIdentityPoint()
	if msg.Sign1.Di.Equal(identity) == 1 || msg.Sign1.Ei.Equal(identity) == 1 {
		return rounds.NewError(id, errors.New("commitment Ei or Di was the identity"))
	}
	party := round.Parties[id]
	party.Di.Set(&msg.Sign1.Di)
	party.Ei.Set(&msg.Sign1.Ei)
	return nil
}

func (round *round1) computeRhos() {
	/*
		While profiling, we noticed that using hash.Hash forces all values to be allocated on the heap.
		To prevent this, we can simply create a big buffer on the stack and call sha512.Sum().

		We need to compute a very simple hash N times, and Go's caching isn't great for hashing.
		Therefore, we can simply change the buffer and rehash it many times.
	*/
	messageHash := sha512.Sum512(round.Message)

	sizeB := int(round.N() * (party.ByteSize + 32 + 32))
	bufferHeader := len(hashDomainSeparation) + party.ByteSize + len(messageHash)
	sizeBuffer := bufferHeader + sizeB
	offsetID := len(hashDomainSeparation)

	// We compute the binding factor 𝜌_i for each party as such:
	//
	//     𝜌_d = SHA-512 ("FROST-SHA512" || i || SHA-512(Message) || B )
	//
	// For each party ID i.
	//
	// The list B is the concatenation of ( j || D_j || E_j ) for all signers j in sorted order.
	//     B = (ID1 || D_1 || E_1) || (ID_2 || D_2 || E_2) || ... || (ID_N || D_N || E_N)

	// We compute the big buffer "FROST-SHA512" || ... || SHA-512(Message) || B
	// and remember the offset of ... . Later we will write the ID of each party at this place.
	buffer := make([]byte, 0, sizeBuffer)
	buffer = append(buffer, hashDomainSeparation...)
	buffer = append(buffer, round.SelfID().Bytes()...)
	buffer = append(buffer, messageHash[:]...)

	// compute B
	for _, id := range round.AllPartyIDs() {
		party := round.Parties[id]
		buffer = append(buffer, id.Bytes()...)
		buffer = append(buffer, party.Di.Bytes()...)
		buffer = append(buffer, party.Ei.Bytes()...)
	}

	for id, party := range round.Parties {
		// Update the four bytes with the ID
		copy(buffer[offsetID:], id.Bytes())

		// Pi = ρ = H ("FROST-SHA512" || Message || B || ID )
		digest := sha512.Sum512(buffer)
		party.Pi.SetUniformBytes(digest[:])
	}
}

func (round *round1) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	round.computeRhos()

	round.R.Set(edwards25519.NewIdentityPoint())
	for _, p := range round.Parties {
		// TODO Find a way to do this faster since we don't need constant time
		// Ri = D + [ρ] E
		p.Ri.ScalarMult(&p.Pi, &p.Ei)
		p.Ri.Add(&p.Ri, &p.Di)

		// R += Ri
		round.R.Add(&round.R, &p.Ri)
	}

	// c = H(R, GroupKey, M)
	round.C.Set(eddsa.ComputeChallenge(&round.R, round.GroupKey, round.Message))

	selfID := round.SelfID()
	selfParty := round.Parties[selfID]

	// Compute z = d + (e • ρ) + 𝛌 • s • c
	// Note: since we multiply the secret by the Lagrange coefficient,
	// can ignore 𝛌=1
	secretShare := &selfParty.Zi
	secretShare.Multiply(&round.SecretKeyShare, &round.C)         // s • c
	secretShare.MultiplyAdd(&round.e, &selfParty.Pi, secretShare) // (e • ρ) + s • c
	secretShare.Add(secretShare, &round.d)                        // d + (e • ρ) + 𝛌 • s • c

	msg := messages.NewSign2(selfID, secretShare)

	return []*messages.Message{msg}, nil
}

func (round *round1) NextRound() rounds.Round {
	return &round2{round}
}
