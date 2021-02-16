package messages

import (
	"fmt"

	"filippo.io/edwards25519"
)

const SignSize1 = 32 + 32

type Sign1 struct {
	Di, Ei edwards25519.Point
}

func NewSign1(from uint32, CommitmentD, CommitmentE *edwards25519.Point) *Message {
	var msg Sign1

	msg.Di.Set(CommitmentD)
	msg.Ei.Set(CommitmentE)

	return &Message{
		Type:  MessageTypeSign1,
		From:  from,
		Sign1: &msg,
	}

}

func (m *Sign1) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, m.Di.Bytes()...)
	existing = append(existing, m.Ei.Bytes()...)
	return existing, nil
}

// Encode creates a []byte slice with [MsgType + From + Di + Ei]
func (m *Sign1) MarshalBinary() ([]byte, error) {
	var buf [SignSize1]byte
	return m.BytesAppend(buf[:0])
}

func (m *Sign1) UnmarshalBinary(data []byte) error {
	var err error

	if len(data) != SignSize1 {
		return fmt.Errorf("msg1: %w", ErrInvalidMessage)
	}

	_, err = m.Di.SetBytes(data[:32])
	if err != nil {
		return fmt.Errorf("msg1.D: %w", err)
	}

	_, err = m.Ei.SetBytes(data[32:])
	if err != nil {
		return fmt.Errorf("msg1.E: %w", err)
	}

	return nil
}

func (m *Sign1) Size() int {
	return SignSize1
}
