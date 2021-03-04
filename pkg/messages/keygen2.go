package messages

import (
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

const sizeKeygen2 = 32

type KeyGen2 struct {
	Share edwards25519.Scalar
}

func NewKeyGen2(from, to party.ID, share *edwards25519.Scalar) *Message {
	return &Message{
		Type:    MessageTypeKeyGen2,
		From:    from,
		To:      to,
		KeyGen2: &KeyGen2{Share: *share},
	}
}

func (m *KeyGen2) BytesAppend(existing []byte) ([]byte, error) {
	return append(existing, m.Share.Bytes()...), nil
}

func (m *KeyGen2) MarshalBinary() ([]byte, error) {
	var buf [sizeKeygen2]byte
	return m.BytesAppend(buf[:0])
}

func (m *KeyGen2) UnmarshalBinary(data []byte) error {
	if len(data) != sizeKeygen2 {
		return fmt.Errorf("msg2: %w", ErrInvalidMessage)
	}

	_, err := m.Share.SetCanonicalBytes(data)
	return err
}

func (m *KeyGen2) Size() int {
	return sizeKeygen2
}

func (m *KeyGen2) Equal(other interface{}) bool {
	otherMsg, ok := other.(*KeyGen2)
	if !ok {
		return false
	}
	if otherMsg.Share.Equal(&m.Share) != 1 {
		return false
	}
	return true
}
