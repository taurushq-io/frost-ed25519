package messages

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const sizeKeygen2 = 32

type KeyGen2 struct {
	// Share is a Shamir additive share for the destination party
	Share ristretto.Scalar
}

func NewKeyGen2(from, to party.ID, share *ristretto.Scalar) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeKeyGen2,
			From: from,
			To:   to,
		},
		KeyGen2: &KeyGen2{Share: *share},
	}
}

func (m *KeyGen2) BytesAppend(existing []byte) ([]byte, error) {
	return append(existing, m.Share.Bytes()...), nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *KeyGen2) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, sizeKeygen2)
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
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
