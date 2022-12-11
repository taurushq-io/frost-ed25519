package signer

import (
	"crypto/sha512"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

var hashDomainSeparation = []byte("FROST-SHA512")

func (round *Round1Signer) ProcessMessage(msg *messages.Message) *state.Error {
	round.Message = msg.SignRequest.Msg
	for i := 0; i < len(msg.SignRequest.Nonces); i++ {
		otherParty := round.Parties[msg.SignRequest.Nonces[i].PartyID]
		identity := ristretto.NewIdentityElement()

		if msg.SignRequest.Nonces[i].Di.Equal(identity) == 1 || msg.SignRequest.Nonces[i].Ei.Equal(identity) == 1 {
			return state.NewError(msg.SignRequest.Nonces[i].PartyID, errors.New("commitment Ei or Di was the identity"))
		}
		otherParty.Di.Set(&msg.SignRequest.Nonces[i].Di)
		otherParty.Ei.Set(&msg.SignRequest.Nonces[i].Ei)
	}
	return nil
}

func (round *Round1Signer) computeRhos() {
	/*
		While profiling, we noticed that using hash.Hash forces all values to be allocated on the heap.
		To prevent this, we can simply create a big buffer on the stack and call sha512.Sum().

		We need to compute a very simple hash N times, and Go's caching isn't great for hashing.
		Therefore, we can simply change the buffer and rehash it many times.
	*/
	messageHash := sha512.Sum512(round.Message)

	sizeB := int(round.PartyIDs().N() * (party.IDByteSize + 32 + 32))
	bufferHeader := len(hashDomainSeparation) + party.IDByteSize + len(messageHash)
	sizeBuffer := bufferHeader + sizeB

	// We compute the binding factor 𝜌_{i} for each party as such:
	//
	//	   For FROST1:
	//
	//     𝜌_d = SHA-512 ("FROST-SHA512" ∥ i ∥ SHA-512(Message) ∥ B )
	//
	// 	   For each party ID i.
	//
	//     For FROST2:
	//
	//	   𝜌 = SHA-512 ("FROST-SHA512" ∥ SHA-512(Message) ∥ B )
	//
	// 	   Once.
	//
	// The list B is the concatenation of ( j ∥ Dⱼ ∥ Eⱼ ) for all signers j in sorted order.
	//     B = (ID1 ∥ D₁ ∥ E₁) ∥ (ID_2 ∥ D₂ ∥ E₂) ∥ ... ∥ (ID_N ∥ D_N ∥ E_N)

	// We compute the big buffer "FROST-SHA512" ∥ ... ∥ SHA-512(Message) ∥ B
	// and remember the offset of ... . Later we will write the ID of each party at this place.
	buffer := make([]byte, 0, sizeBuffer)
	buffer = append(buffer, hashDomainSeparation...)
	buffer = append(buffer, messageHash[:]...)

	// compute B
	for _, id := range round.PartyIDs() {
		otherParty := round.Parties[id]
		buffer = append(buffer, id.Bytes()...)
		buffer = append(buffer, otherParty.Di.Bytes()...)
		buffer = append(buffer, otherParty.Ei.Bytes()...)
	}

	// the version is FROST_2, so hash buffer, set P, and return
	// don't hash for each party!
	digest := sha512.Sum512(buffer)
	_, _ = round.P.SetUniformBytes(digest[:])
	return
}

func (round *Round1Signer) GenerateMessages() ([]*messages.Message, *state.Error) {
	round.computeRhos()

	round.R.Set(ristretto.NewIdentityElement())

	E := ristretto.NewIdentityElement()
	for _, p := range round.Parties {
		// R += Di
		round.R.Add(&round.R, &p.Di)
		// E += Ei
		E.Add(E, &p.Ei)
	}

	// E = [ρ] E
	E.ScalarMult(&round.P, E)
	// R += E
	round.R.Add(&round.R, E)

	// c = H(R, GroupKey, M)
	round.C.Set(eddsa.ComputeChallenge(&round.R, &round.GroupKey, round.Message))

	selfParty := round.Parties[round.SelfID()]

	// Compute z = d + (e • ρ) + 𝛌 • s • c
	// Note: since we multiply the secret by the Lagrange coefficient,
	// can ignore 𝛌=1
	secretShare := &selfParty.Zi
	secretShare.Multiply(&round.SecretKeyShare, &round.C) // s • c

	secretShare.MultiplyAdd(&round.e, &round.P, secretShare) // (e • ρ) + s • c

	secretShare.Add(secretShare, &round.d) // d + (e • ρ) + 𝛌 • s • c

	msg := messages.NewSign2(round.SelfID(), secretShare)

	return []*messages.Message{msg}, nil
}

func (round *Round1Signer) NextRound() state.Round {
	return nil
}
