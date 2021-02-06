package messages

import (
	"fmt"

	"filippo.io/edwards25519"
)

const KeyGenSize2 = 32

type KeyGen2 struct {
	Share *edwards25519.Scalar
}

func NewKeyGen2(from, to uint32, Share *edwards25519.Scalar) *Message {
	return &Message{
		Type: MessageTypeKeyGen2,
		From: from,
		To:   to,
		KeyGen2: &KeyGen2{
			Share: edwards25519.NewScalar().Set(Share),
		},
	}
}

func (m *KeyGen2) BytesAppend(existing []byte) ([]byte, error) {
	if m.Share == nil {
		return nil, fmt.Errorf("msg2: %w", ErrInvalidMessage)
	}
	existing = append(existing, m.Share.Bytes()...)
	return existing, nil
}

func (m *KeyGen2) MarshalBinary() ([]byte, error) {
	var buf [KeyGenSize2]byte
	return m.BytesAppend(buf[:0])
}

func (m *KeyGen2) UnmarshalBinary(data []byte) error {
	var err error

	if len(data) != KeyGenSize2 {
		return fmt.Errorf("msg2: %w", ErrInvalidMessage)
	}

	m.Share, err = edwards25519.NewScalar().SetCanonicalBytes(data)
	if err != nil {
		return err
	}

	return nil
}

func (m *KeyGen2) Size() int {
	return KeyGenSize2
}
