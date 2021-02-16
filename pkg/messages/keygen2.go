package messages

import (
	"fmt"

	"filippo.io/edwards25519"
)

const KeyGenSize2 = 32

type KeyGen2 struct {
	Share edwards25519.Scalar
}

func NewKeyGen2(from, to uint32, Share *edwards25519.Scalar) *Message {
	var kg KeyGen2
	var msg Message
	kg.Share.Set(Share)
	msg.Type = MessageTypeKeyGen2
	msg.From = from
	msg.To = to
	msg.KeyGen2 = &kg
	return &msg
}

func (m *KeyGen2) BytesAppend(existing []byte) ([]byte, error) {
	//if m.Share == nil {
	//	return nil, fmt.Errorf("msg2: %w", ErrInvalidMessage)
	//}
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

	_, err = m.Share.SetCanonicalBytes(data)
	if err != nil {
		return err
	}

	return nil
}

func (m *KeyGen2) Size() int {
	return KeyGenSize2
}
