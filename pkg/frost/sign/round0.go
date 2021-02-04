package sign

import (
	"crypto/rand"
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/frost/messages"
)

var (
	ErrMessageNotForSelf = errors.New("message is not addressed to us")
	ErrNoSignContent     = errors.New("message does not contain sign content")
	ErrInvalidSender     = errors.New("message sender is not in set of signers")
	ErrDuplicateMessage  = errors.New("message already received from party")
	ErrMessageStore      = errors.New("could not find message to store")
	ErrRoundProcessed    = errors.New("round was already processed")
)

type round0 struct {
	PartySelf uint32
	Secret    *frost.PartySecret

	// AllParties is a sorted array of party IDs
	AllParties []uint32

	// Message is the message to be signed
	Message []byte

	// Parties maps IDs to a struct containing all intermediary data for each Signer
	Parties map[uint32]*Signer
	Y       *frost.PublicKey

	// e and d are the scalars committed to in the first round
	e, d edwards25519.Scalar

	// C = H(R, Y, Message)
	C edwards25519.Scalar
	// R = ∑ Ri
	R edwards25519.Point

	// msgs1, msgs2 contain the messages received from the other parties.
	msgs1 map[uint32]*messages.Sign1
	msgs2 map[uint32]*messages.Sign2
}

func (r *round0) StoreMessage(message *messages.Message) error {
	if message.From == r.PartySelf {
		return nil
	}

	switch message.Type {
	case messages.MessageTypeSign1:
		if _, ok := r.msgs1[message.From]; ok {
			return ErrDuplicateMessage
		}
		r.msgs1[message.From] = message.Sign1
		return nil

	case messages.MessageTypeSign2:
		if _, ok := r.msgs2[message.From]; ok {
			return ErrDuplicateMessage
		}
		r.msgs2[message.From] = message.Sign2
		return nil
	}

	return ErrMessageStore
}

func (r *round0) CanProcess() bool {
	return true
}

func (r *round0) ProcessRound() ([]*messages.Message, error) {
	buf := make([]byte, 64)
	rand.Read(buf)
	r.e.SetUniformBytes(buf)
	rand.Read(buf)
	r.d.SetUniformBytes(buf)

	party := r.Parties[r.PartySelf]
	party.Di.ScalarBaseMult(&r.d)
	party.Ei.ScalarBaseMult(&r.e)

	msg := messages.NewSign1(r.PartySelf, &party.Di, &party.Ei)

	return []*messages.Message{msg}, nil
}

func (r *round0) NextRound() frost.Round {
	return &round1{r}
}

func (r *round0) IsOtherParticipant(p uint32) bool {
	if p == r.PartySelf {
		return false
	}
	_, ok := r.Parties[p]

	return ok
}

func (r *round0) Reset() {
	//zero := edwards25519.NewScalar()
	//identity := edwards25519.NewIdentityPoint()
}

func NewRound(selfID uint32, parties map[uint32]*frost.Party, partyIDs []uint32, secret *frost.PartySecret, message []byte) (frost.Round, error) {
	var r round0
	N := len(partyIDs)

	if selfID != secret.Index {
		return nil, errors.New("secret data and ID don't match")
	}
	if selfID == 0 {
		return nil, errors.New("id 0 is not valid")
	}

	r = round0{
		PartySelf:  selfID,
		Secret:     secret,
		AllParties: partyIDs,
		Parties:    make(map[uint32]*Signer, N),
		Y:          new(frost.PublicKey),
		Message:    message,
		msgs1:      make(map[uint32]*messages.Sign1, N),
		msgs2:      make(map[uint32]*messages.Sign2, N),
	}

	found := false
	for _, id := range partyIDs {
		if id == selfID {
			found = true
		}
		if id == 0 {
			return nil, errors.New("id 0 is not valid")
		}
		if id != parties[id].Index {
			return nil, errors.New("ID of party does not match")
		}
		r.Parties[id] = NewSigner(parties[id])
	}
	if !found {
		return nil, errors.New("secret data and ID don't match")
	}

	pk, err := frost.ComputeGroupKey(parties)
	if err != nil {
		return nil, err
	}
	r.Y = pk
	return &r, nil
}
