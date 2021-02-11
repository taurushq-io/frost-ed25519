package sign

import (
	"errors"
	"fmt"
	"sync"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
)

type (
	base struct {
		PartySelf uint32
		Secret    *edwards25519.Scalar

		// AllParties is a sorted array of party IDs
		AllParties []uint32

		// Message is the message to be signed
		Message []byte

		// Parties maps IDs to a struct containing all intermediary data for each signer
		Parties map[uint32]*signer
		Y       edwards25519.Point

		// e and d are the scalars committed to in the first round
		e, d edwards25519.Scalar

		// C = H(R, Y, Message)
		C edwards25519.Scalar
		// R = ∑ Ri
		R edwards25519.Point

		messages *messages.Queue

		messagesProcessed, roundProcessed bool

		output chan struct{}

		// Signature to be output
		Signature *eddsa.Signature

		sync.Mutex
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
)

func NewRound(selfID uint32, publicKeys map[uint32]*eddsa.PublicKey, partyIDs []uint32, secret *edwards25519.Scalar, message []byte) (frost.Round, error) {
	var pk edwards25519.Point
	// Check that the 0 ID is never used
	if selfID == 0 {
		return nil, errors.New("id 0 is not valid")
	}

	// Remove all duplicates and occurrences of selfID from partyIDs
	othersMap := map[uint32]struct{}{}
	for _, id := range partyIDs {
		if selfID == id {
			continue
		}
		othersMap[id] = struct{}{}
	}

	N := len(partyIDs)

	pk.Set(edwards25519.NewIdentityPoint())
	signers := make(map[uint32]*signer, N)
	for _, id := range partyIDs {
		if id == 0 {
			return nil, errors.New("id 0 is not valid")
		}

		pkShare, ok := publicKeys[id]
		if !ok {
			return nil, errors.New("missing public key of ...")
		}

		lagrange := polynomial.LagrangeCoefficient(id, partyIDs)

		signers[id] = new(signer)
		signers[id].Public.ScalarMult(lagrange, pkShare.Point)

		signers[id].Lagrange.Set(lagrange)
		pk.Add(&pk, &signers[id].Public)
	}
	if _, ok := signers[selfID]; !ok {
		return nil, errors.New("secret data and ID don't match")
	}

	accepted := []messages.MessageType{messages.MessageTypeSign1, messages.MessageTypeSign2}
	messagesHolder, err := messages.NewMessageHolder(selfID, othersMap, accepted)
	if err != nil {
		return nil, fmt.Errorf("failed to create messageHolder: %w", err)
	}

	r := base{
		PartySelf:  selfID,
		Secret:     secret,
		AllParties: partyIDs,
		Parties:    signers,
		Y:          pk,
		Message:    message,
		messages:   messagesHolder,
		output:     make(chan struct{}),
	}

	return &r, nil
}

func (round *base) StoreMessage(message *messages.Message) error {
	return round.messages.Store(message)
}

func (round *base) Reset() {
}

func (round *base) ID() uint32 {
	return round.PartySelf
}

func (round *base) CanStart() bool {
	return true
}

func (round *round1) CanStart() bool {
	round.Lock()
	defer round.Unlock()
	return round.messages.ReceivedAll()
}
