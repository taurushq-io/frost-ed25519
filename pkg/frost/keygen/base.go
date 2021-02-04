package keygen

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/frost/messages"
	"github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"
)

type base struct {
	PartySelf  uint32
	AllParties []uint32

	Parties map[uint32]*KeyGenerator

	polynomial     *polynomial.Polynomial
	receivedShared []*edwards25519.Scalar

	msgs1 map[uint32]*messages.Sign1
	msgs2 map[uint32]*messages.Sign2
}

//func (r *base) StoreMessage(message []byte) error {
//	var err error
//	msgType := frost.MessageType(message[0])
//	switch msgType {
//	case frost.MessageTypeKeyGen1:
//		msg := new(Sign2)
//		err = msg.UnmarshalBinary(message[1:])
//		if err != nil {
//			return err
//		}
//
//	case frost.MessageTypeKeyGen2:
//		msg := new(Sign2)
//		err = msg.UnmarshalBinary(message[1:])
//		if err != nil {
//			return err
//		}
//
//
//	}
//
//	if !r.IsOtherParticipant(from) {
//		return ErrInvalidSender
//	}
//
//	switch msgType {
//	case frost.MessageTypeSign1:
//		if _, ok := r.msgs1[from]; ok {
//			return ErrDuplicateMessage
//		}
//		msg, err := new(Sign1).Decode(content)
//		if err != nil {
//			return err
//		}
//		r.msgs1[from] = msg
//		return nil
//
//	case frost.MessageTypeSign2:
//		if _, ok := r.msgs2[from]; ok {
//			return ErrDuplicateMessage
//		}
//
//		msg, err := new(Sign2).Decode(content)
//		if err != nil {
//			return err
//		}
//
//		r.msgs2[from] = msg
//		return nil
//	}
//
//	return ErrMessageStore
//}

//func (r *base) CanProcess() bool {
//	return true
//}
//
//func (r *base) ProcessRound() ([][]byte, error) {
//	buf := make([]byte, 64)
//	_, err := rand.Read(buf)
//	if err != nil {
//		return nil, err
//	}
//	r.e = new(edwards25519.Scalar).SetUniformBytes(buf)
//	_, err = rand.Read(buf)
//	if err != nil {
//		return nil, err
//	}
//	r.d = new(edwards25519.Scalar).SetUniformBytes(buf)
//
//	party := r.Parties[r.PartySelf]
//	party.Di = edwards25519.NewIdentityPoint().ScalarBaseMult(r.d)
//	party.Ei = edwards25519.NewIdentityPoint().ScalarBaseMult(r.e)
//
//	msg := Sign1{
//		Di: party.Di,
//		Ei: party.Ei,
//	}
//	msgByte, err := msg.Encode(r.PartySelf)
//	if err != nil {
//		return nil, err
//	}
//
//	return [][]byte{msgByte}, nil
//}
//
//func (r *base) NextRound() frost.Round {
//	return &round1{r}
//}
//
//func (r *round0) IsOtherParticipant(p uint32) bool {
//	if p == r.PartySelf {
//		return false
//	}
//	_, ok := r.Parties[p]
//
//	return ok
//}
//
//func (r *base) Reset() {
//	//zero := edwards25519.NewScalar()
//	//identity := edwards25519.NewIdentityPoint()
//}
//
//func NewRound(selfID uint32, parties map[uint32]*frost.Party, partyIDs []uint32, secret *frost.PartySecret, message []byte) frost.Round {
//	N := len(partyIDs)
//	r := &round0{
//		PartySelf:  selfID,
//		Secret:     secret,
//		AllParties: partyIDs,
//		Parties:    make(map[uint32]*Signer, N),
//		Y:   new(frost.PublicKey),
//		e:          edwards25519.NewScalar(),
//		d:          edwards25519.NewScalar(),
//		Message:    message,
//		C: edwards25519.NewScalar(),
//		Ri:          edwards25519.NewIdentityPoint(),
//		msgs1:      make(map[uint32]*Sign1, N),
//		msgs2:      make(map[uint32]*Sign2, N),
//		canProceed: true,
//	}
//
//	for _, id := range partyIDs {
//		r.Parties[id] = NewSigner(parties[id])
//	}
//
//	pk, err := frost.ComputeGroupKey(parties)
//	if err != nil {
//		panic(err)
//	}
//	r.Y = pk
//	return r
//}
