package messages

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const sizeSign2 = 32

type Sign2 struct {
	// Zi is a ristretto.Scalar.
	// It represents the sender's share of the 's' part of the final signature
	Zi ristretto.Scalar
}

func NewSign2(from party.ID, signatureShare *ristretto.Scalar) *Message {
	return &Message{
		messageType: MessageTypeSign2,
		from:        from,
		Sign2:       &Sign2{Zi: *signatureShare},
	}
}

func (m *Sign2) BytesAppend(existing []byte) ([]byte, error) {
	return append(existing, m.Zi.Bytes()...), nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *Sign2) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, sizeSign2)
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *Sign2) UnmarshalBinary(data []byte) error {
	if len(data) != sizeSign2 {
		return fmt.Errorf("msg2: %w", ErrInvalidMessage)
	}

	_, err := m.Zi.SetCanonicalBytes(data)
	if err != nil {
		return fmt.Errorf("msg2.Zi: %w", err)
	}

	return nil
}

func (m *Sign2) Size() int {
	return sizeSign2
}

func (m *Sign2) Equal(other interface{}) bool {
	otherMsg, ok := other.(*Sign2)
	if !ok {
		return false
	}
	if otherMsg.Zi.Equal(&m.Zi) != 1 {
		return false
	}
	return true
}
