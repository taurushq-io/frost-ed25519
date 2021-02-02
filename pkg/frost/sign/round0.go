package sign

import (
	"crypto/rand"
	"errors"
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/frost"
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

	// Parties maps IDs to a struct containing all intermediary data for each Signer
	Parties  map[uint32]*Signer
	GroupKey *frost.PublicKey
	//GroupKey *edwards25519.Point

	// e and d are the scalars committed to in the first round
	e, d *edwards25519.Scalar

	// Message is the message to be signed
	Message    []byte
	Commitment *edwards25519.Scalar
	R          *edwards25519.Point

	// msgs1, msgs2 contain the messages received from the other parties.
	msgs1 map[uint32]*Msg1
	msgs2 map[uint32]*Msg2

	canProceed bool
}

func (r *round0) StoreMessage(message []byte) error {
	from, msgType, content := frost.DecodeBytes(message)

	if from == r.PartySelf {
		// TODO
		return nil
		//return ErrMessageNotForSelf
	}

	if !r.IsOtherParticipant(from) {
		return ErrInvalidSender
	}

	switch msgType {
	case frost.MessageTypeSign1:
		if _, ok := r.msgs1[from]; ok {
			return ErrDuplicateMessage
		}
		msg, err := new(Msg1).Decode(content)
		if err != nil {
			return err
		}
		r.msgs1[from] = msg
		return nil

	case frost.MessageTypeSign2:
		if _, ok := r.msgs2[from]; ok {
			return ErrDuplicateMessage
		}

		msg, err := new(Msg2).Decode(content)
		if err != nil {
			return err
		}

		r.msgs2[from] = msg
		return nil
	}

	return ErrMessageStore
}

func (r *round0) CanProcess() bool {
	return true
}

func (r *round0) ProcessRound() ([][]byte, error) {
	buf := make([]byte, 64)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	r.e = new(edwards25519.Scalar).SetUniformBytes(buf)
	_, err = rand.Read(buf)
	if err != nil {
		return nil, err
	}
	r.d = new(edwards25519.Scalar).SetUniformBytes(buf)

	party := r.Parties[r.PartySelf]
	party.CommitmentD = new(edwards25519.Point).ScalarBaseMult(r.d)
	party.CommitmentE = new(edwards25519.Point).ScalarBaseMult(r.e)

	msg := Msg1{
		CommitmentD: party.CommitmentD,
		CommitmentE: party.CommitmentE,
	}
	msgByte, err := msg.Encode(r.PartySelf)
	if err != nil {
		return nil, err
	}

	return [][]byte{msgByte}, nil
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

func NewRound(selfID uint32, parties map[uint32]*frost.Party, partyIDs []uint32, secret *frost.PartySecret, message []byte) frost.Round {
	N := len(partyIDs)
	r := &round0{
		PartySelf:  selfID,
		Secret:     secret,
		AllParties: partyIDs,
		Parties:    make(map[uint32]*Signer, N),
		GroupKey:   new(frost.PublicKey),
		e:          edwards25519.NewScalar(),
		d:          edwards25519.NewScalar(),
		Message:    message,
		Commitment: edwards25519.NewScalar(),
		R:          edwards25519.NewIdentityPoint(),
		msgs1:      make(map[uint32]*Msg1, N),
		msgs2:      make(map[uint32]*Msg2, N),
		canProceed: true,
	}

	for _, id := range partyIDs {
		r.Parties[id] = NewSigner(parties[id])
	}

	pk, err := frost.ComputeGroupKey(parties)
	if err != nil {
		panic(err)
	}
	r.GroupKey = pk
	return r
}
