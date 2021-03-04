package messages

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

type Message struct {
	Type     MessageType
	From, To party.ID
	KeyGen1  *KeyGen1
	KeyGen2  *KeyGen2
	Sign1    *Sign1
	Sign2    *Sign2
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

// headerSize is
//  1 for MessageType
//  4 for Sender
//  4 for receiver
const headerSize = 1 + 2*party.ByteSize

func (m *Message) BytesAppend(existing []byte) (data []byte, err error) {
	var header [headerSize]byte
	header[0] = byte(m.Type)
	offset := 1
	copy(header[offset:], m.From.Bytes())
	offset += party.ByteSize
	copy(header[offset:], m.To.Bytes())
	offset += party.ByteSize
	existing = append(existing, header[:]...)

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
	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			return headerSize + m.KeyGen1.Size()
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			return headerSize + m.KeyGen2.Size()
		}
	case MessageTypeSign1:
		if m.Sign1 != nil {
			return headerSize + m.Sign1.Size()
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			return headerSize + m.Sign2.Size()
		}
	}
	panic("message contains no data")
}

func (m *Message) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, m.Size())
	return m.BytesAppend(buf)
}

func (m *Message) UnmarshalBinary(data []byte) error {
	msgType := MessageType(data[0])
	m.Type = msgType
	data = data[1:]
	m.From = party.FromBytes(data)
	data = data[party.ByteSize:]

	m.To = party.FromBytes(data)
	data = data[party.ByteSize:]

	switch msgType {
	case MessageTypeKeyGen1:
		var keygen1 KeyGen1
		m.KeyGen1 = &keygen1
		return m.KeyGen1.UnmarshalBinary(data)

	case MessageTypeKeyGen2:
		var keygen2 KeyGen2
		m.KeyGen2 = &keygen2
		return m.KeyGen2.UnmarshalBinary(data)

	case MessageTypeSign1:
		var sign1 Sign1
		m.Sign1 = &sign1

		return m.Sign1.UnmarshalBinary(data)

	case MessageTypeSign2:
		var sign2 Sign2
		m.Sign2 = &sign2
		return m.Sign2.UnmarshalBinary(data)
	}
	return errors.New("message type not recognized")
}

func (m *Message) Equal(other interface{}) bool {
	otherMsg, ok := other.(*Message)
	if !ok {
		return false
	}

	if m.Type != otherMsg.Type {
		return false
	}

	if m.From != otherMsg.From {
		return false
	}

	if m.To != otherMsg.To {
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
