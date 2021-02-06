package sign

import (
	"crypto/rand"
	"errors"
	"sync"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
)

type base struct {
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

	// msgs1, msgs2 contain the messages received from the other parties.
	msgs1 map[uint32]*messages.Sign1
	msgs2 map[uint32]*messages.Sign2

	readyForNextRound bool
	sync.Mutex
}

func (round *base) StoreMessage(message *messages.Message) error {
	round.Lock()
	defer round.Unlock()

	if message.Sign1 == nil && message.Sign2 == nil {
		return frost.ErrNoSignContent
	}

	if message.From == round.PartySelf {
		return nil
	}
	if !round.isOtherParticipant(message.From) {
		return frost.ErrInvalidSender
	}

	switch message.Type {
	case messages.MessageTypeSign1:
		if _, ok := round.msgs1[message.From]; ok {
			return frost.ErrDuplicateMessage
		}
		round.msgs1[message.From] = message.Sign1
		return nil

	case messages.MessageTypeSign2:
		if _, ok := round.msgs2[message.From]; ok {
			return frost.ErrDuplicateMessage
		}
		round.msgs2[message.From] = message.Sign2
		return nil
	}

	return frost.ErrMessageStore
}

func (round *base) CanProcess() bool {
	return !round.readyForNextRound
}

func (round *base) ProcessRound() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return nil, frost.ErrRoundProcessed
	}

	buf := make([]byte, 64)
	rand.Read(buf)
	round.e.SetUniformBytes(buf)
	rand.Read(buf)
	round.d.SetUniformBytes(buf)

	party := round.Parties[round.PartySelf]
	party.Di.ScalarBaseMult(&round.d)
	party.Ei.ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.PartySelf, &party.Di, &party.Ei)

	round.readyForNextRound = true
	return []*messages.Message{msg}, nil
}

func (round *base) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		round.readyForNextRound = false
		return &round1{round}
	}
	return round
}

func NewRound(selfID uint32, publicKeys map[uint32]*eddsa.PublicKey, partyIDs []uint32, secret *edwards25519.Scalar, message []byte) (frost.Round, error) {
	var pk edwards25519.Point
	N := len(partyIDs)

	// Check that the 0 ID is never used
	if selfID == 0 {
		return nil, errors.New("id 0 is not valid")
	}

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
		signers[id].Public.ScalarMult(lagrange, &pkShare.Point)

		signers[id].Lagrange.Set(lagrange)
		pk.Add(&pk, &signers[id].Public)
	}
	if _, ok := signers[selfID]; !ok {
		return nil, errors.New("secret data and ID don't match")
	}

	r := base{
		PartySelf:  selfID,
		Secret:     secret,
		AllParties: partyIDs,
		Parties:    signers,
		Y:          pk,
		Message:    message,
		msgs1:      make(map[uint32]*messages.Sign1, N),
		msgs2:      make(map[uint32]*messages.Sign2, N),
	}

	return &r, nil
}

func (round *base) Reset() {
	//zero := edwards25519.NewScalar()
	//identity := edwards25519.NewIdentityPoint()
}

// isOtherParticipant indicates whether p is one of the parties we are currently signing with.
func (round *base) isOtherParticipant(p uint32) bool {
	if p == round.PartySelf {
		return false
	}
	_, ok := round.Parties[p]

	return ok
}

func (round *base) ID() uint32 {
	return round.PartySelf
}
