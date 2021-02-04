package messages

import (
	"filippo.io/edwards25519"
	"fmt"
)

const SignSize3 = 64

type Sign3 struct {
	Sig [64]byte
}

func NewSign3(R *edwards25519.Point, s *edwards25519.Scalar) *Message {
	msg := new(Sign3)
	copy(msg.Sig[0:32], R.Bytes())
	copy(msg.Sig[32:64], s.Bytes())
	return &Message{
		Type:  MessageTypeSign3,
		Sign3: msg,
	}
}

func (m *Sign3) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, m.Sig[:]...)
	return existing, nil
}

// Encode creates a []byte slice with [MsgType + From + Di + Ei]
func (m *Sign3) MarshalBinary() ([]byte, error) {
	var buf [SignSize3]byte
	return m.BytesAppend(buf[:0])
}

func (m *Sign3) UnmarshalBinary(data []byte) error {

	if len(data) != SignSize3 {
		return fmt.Errorf("msg3: %w", ErrInvalidMessage)
	}

	copy(m.Sig[:], data)

	return nil
}

func (m *Sign3) Size() int {
	return SignSize3
}
