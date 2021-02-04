package messages

import (
	"fmt"

	"filippo.io/edwards25519"
)

const SignSize2 = 32

type Sign2 struct {
	// Zi is a edwards25519.Scalar.
	// It represents the sender's share of the 's' part of the final signature
	Zi edwards25519.Scalar
}

func NewSign2(from uint32, SignatureShare *edwards25519.Scalar) *Message {
	var msg Sign2

	msg.Zi.Set(SignatureShare)

	return &Message{
		Type:  MessageTypeSign2,
		From:  from,
		Sign2: &msg,
	}
}

func (m *Sign2) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, m.Zi.Bytes()...)
	return existing, nil
}

// Encode creates a []byte slice with [MsgType + From + Zi]
func (m *Sign2) MarshalBinary() ([]byte, error) {
	var buf [SignSize2]byte
	return m.BytesAppend(buf[:0])
}

func (m *Sign2) UnmarshalBinary(data []byte) error {
	var err error
	if len(data) != SignSize2 {
		return fmt.Errorf("msg2: %w", ErrInvalidMessage)
	}

	_, err = m.Zi.SetCanonicalBytes(data[:32])
	if err != nil {
		return fmt.Errorf("msg2.Zi: %w", err)
	}

	return nil
}

func (m *Sign2) Size() int {
	return SignSize2
}
