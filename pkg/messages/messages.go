package messages

import (
	"errors"
	"fmt"
)

type Message struct {
	Header
	KeyGen1 *KeyGen1
	KeyGen2 *KeyGen2
	Sign1   *Sign1
	Sign2   *Sign2
}

var ErrInvalidMessage = errors.New("invalid message")

type MessageType uint8

// MessageType s must be increasing.
const (
	MessageTypeNone MessageType = iota
	MessageTypeKeyGen1
	MessageTypeKeyGen2
	MessageTypeSign1
	MessageTypeSign2
)

func (m *Message) BytesAppend(existing []byte) (data []byte, err error) {
	existing, err = m.Header.BytesAppend(existing)
	if err != nil {
		return nil, fmt.Errorf("message.BytesAppend: %w", err)
	}

	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			return m.KeyGen1.BytesAppend(existing)
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			return m.KeyGen2.BytesAppend(existing)
		}
	case MessageTypeSign1:
		if m.Sign1 != nil {
			return m.Sign1.BytesAppend(existing)
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			return m.Sign2.BytesAppend(existing)
		}
	}

	return nil, errors.New("message does not contain any data")
}

func (m *Message) Size() int {
	var size int
	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			size = m.KeyGen1.Size()
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			size = m.KeyGen2.Size()
		}
	case MessageTypeSign1:
		if m.Sign1 != nil {
			size = m.Sign1.Size()
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			size = m.Sign2.Size()
		}
	}
	return m.Header.Size() + size
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *Message) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, m.Size())
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *Message) UnmarshalBinary(data []byte) error {
	var err error

	if err = m.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	data = data[m.Header.Size():]

	switch m.Type {
	case MessageTypeKeyGen1:
		var keygen1 KeyGen1
		if err = keygen1.UnmarshalBinary(data); err == nil {
			m.KeyGen1 = &keygen1
		}

	case MessageTypeKeyGen2:
		var keygen2 KeyGen2
		if err = keygen2.UnmarshalBinary(data); err == nil {
			m.KeyGen2 = &keygen2
		}

	case MessageTypeSign1:
		var sign1 Sign1
		if err = sign1.UnmarshalBinary(data); err == nil {
			m.Sign1 = &sign1
		}
	case MessageTypeSign2:
		var sign2 Sign2
		if err = sign2.UnmarshalBinary(data); err == nil {
			m.Sign2 = &sign2
		}
	default:
		return errors.New("messages.UnmarshalBinary: invalid message type")
	}

	return nil
}

func (m *Message) Equal(other interface{}) bool {
	otherMsg, ok := other.(*Message)
	if !ok {
		return false
	}

	if !m.Header.Equal(otherMsg.Header) {
		return false
	}

	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil && otherMsg.KeyGen1 != nil {
			return m.KeyGen1.Equal(otherMsg.KeyGen1)
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil && otherMsg.KeyGen2 != nil {
			return m.KeyGen2.Equal(otherMsg.KeyGen2)
		}
	case MessageTypeSign1:
		if m.Sign1 != nil && otherMsg.Sign1 != nil {
			return m.Sign1.Equal(otherMsg.Sign1)
		}
	case MessageTypeSign2:
		if m.Sign2 != nil && otherMsg.Sign2 != nil {
			return m.Sign2.Equal(otherMsg.Sign2)
		}
	}
	return false
}
