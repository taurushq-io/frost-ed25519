package sign

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/frost"
)

var (
	ErrMessageNotForSelf = errors.New("message is not addressed to us")
	ErrNoSignContent = errors.New("message does not contain sign content")
	ErrInvalidSender = errors.New("message sender is not in set of signers")
	ErrDuplicateMessage = errors.New("message already received from party")
	ErrMessageStore = errors.New("could not find message to store")
	ErrRoundProcessed = errors.New("round was already processed")
)

type round0 struct {
	PartySelf uint32
	Secret *frost.PartySecret

	// AllParties is a sorted array of party IDs
	AllParties []uint32

	// Parties maps IDs to a struct containing all intermediary data for each Signer
	Parties map[uint32]*Signer
	GroupKey *edwards25519.Point

	// e and d are the scalars committed to in the first round
	e, d *edwards25519.Scalar

	// Message is the message to be signed
	Message []byte
	Commitment *edwards25519.Scalar
	R *edwards25519.Point

	// msgs1, msgs2 contain the messages received from the other parties.
	msgs1 map[uint32]*Msg1
	msgs2 map[uint32]*Msg2

	canProceed bool
}

func (r *round0) StoreMessage(message []byte) error {
	from := binary.BigEndian.Uint32(message[0:])
	msgType := MessageType(message[2])
	content := message[3:]


	if from == r.PartySelf {
		return ErrMessageNotForSelf
	}

	if !r.IsOtherParticipant(from) {
		return ErrInvalidSender
	}

	switch msgType {
	case MessageTypeSign1:
		if _, ok := r.msgs1[from]; ok {
			return ErrDuplicateMessage
		}
		msg := new(Msg1)
		copy(msg.CommitmentD, content[:32])
		copy(msg.CommitmentE, content[32:])
		r.msgs1[from] = msg
		return nil

	case MessageTypeSign2:
		if _, ok := r.msgs2[from]; ok {
			return ErrDuplicateMessage
		}

		msg := new(Msg2)
		copy(msg.SignatureShare, content[:32])
		r.msgs2[from] = msg
		return nil
	}


	return ErrMessageStore
}

func (r *round0) CanProcess() bool {
	return true
}

func (r *round0) ProcessRound() ([][]byte, error) {
	if r.canProceed {
		return nil, ErrRoundProcessed
	}
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


	msg := make([]byte, 0, 4 + 1 + 32 + 32)
	binary.BigEndian.PutUint32(msg, r.PartySelf)
	msg = append(msg, byte(MessageTypeSign1))
	msg = append(msg, party.CommitmentD.Bytes()...)
	msg = append(msg, party.CommitmentE.Bytes()...)

	r.canProceed = true
	return [][]byte{msg}, nil
}

func (r *round0) NextRound() frost.Round {
	if r.canProceed {
		r.canProceed = false
		return &round1{r}
	}
	return r
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