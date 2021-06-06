package messages

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

type Message struct {
	messageType MessageType
	from, to    party.ID
	KeyGen1     *KeyGen1
	KeyGen2     *KeyGen2
	Sign1       *Sign1
	Sign2       *Sign2
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
	existing = append(existing, byte(m.messageType))
	existing = append(existing, m.from.Bytes()...)
	existing = append(existing, m.to.Bytes()...)

	switch m.messageType {
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
	switch m.messageType {
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

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *Message) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, m.Size())
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *Message) UnmarshalBinary(data []byte) error {
	var err error
	// ensure the length is long enough to hold the header
	// 1 byte for message type + 2*party.ByteSize for from/to
	if len(data) < 1+2*party.ByteSize {
		return errors.New("data does not contain header")
	}

	msgType := MessageType(data[0])
	m.messageType = msgType
	data = data[1:]
	if m.from, err = party.FromBytes(data); err != nil {
		return err
	}
	data = data[party.ByteSize:]

	if m.to, err = party.FromBytes(data); err != nil {
		return err
	}
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

	if m.messageType != otherMsg.messageType {
		return false
	}

	if m.from != otherMsg.from {
		return false
	}

	if m.to != otherMsg.to {
		return false
	}

	switch m.messageType {
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

// Type returns the MessageType of the message.
func (m *Message) Type() MessageType {
	return m.messageType
}

// From returns the party.ID of the party who sent this message.
func (m *Message) From() party.ID {
	return m.from
}

// To returns the party.ID of the party the message is addressed to.
// If the message is intended for broadcast, the ID returned is 0 (invalid),
// therefore, you should call IsBroadcast() first.
func (m *Message) To() party.ID {
	return m.to
}

// IsBroadcast returns true if the message is intended to be broadcast
func (m *Message) IsBroadcast() bool {
	return m.to == 0
}
