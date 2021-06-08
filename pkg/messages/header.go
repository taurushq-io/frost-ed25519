package messages

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

const headerSize = 1 + 2*party.IDByteSize

type Header struct {
	// Type is the message type
	Type MessageType

	// From returns the party.ID of the party who sent this message.
	// Cannot be 0
	From party.ID

	// To is the party.ID of the party the message is addressed to.
	// If the message is intended for broadcast, the ID returned is 0 (invalid),
	// therefore, you should call IsBroadcast() first.
	To party.ID
}

func (h *Header) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 0, headerSize)
	return h.BytesAppend(data)
}

func (h *Header) UnmarshalBinary(data []byte) error {
	if l := len(data); l < headerSize {
		return fmt.Errorf("Header.UnmarshalBinary: data should be at least %d bytes (got %d)", headerSize, l)
	}

	msgType := MessageType(data[0])
	var (
		from, to party.ID
		err      error
	)
	if from, err = party.FromBytes(data[1:]); err != nil {
		return fmt.Errorf("Header.UnmarshalBinary: from: %w", err)
	}
	if to, err = party.FromBytes(data[1+party.IDByteSize:]); err != nil {
		return fmt.Errorf("Header.UnmarshalBinary: from: %w", err)
	}

	switch msgType {
	case MessageTypeKeyGen1, MessageTypeSign1, MessageTypeSign2:
		if to != 0 {
			return errors.New("Header.UnmarshalBinary: .To field must be 0 to indicate broadcast")
		}
	case MessageTypeKeyGen2:
		if to == 0 {
			return errors.New("Header.UnmarshalBinary: MessageTypeKeyGen2 requires a sender (.To field)")
		}
	default:
		return errors.New("Header.UnmarshalBinary: invalid message type")
	}
	if from == 0 {
		return errors.New("Header.UnmarshalBinary: message must include a non 0 From value")
	}

	h.Type = msgType
	h.From = from
	h.To = to
	return nil
}

func (h *Header) BytesAppend(existing []byte) (data []byte, err error) {
	switch h.Type {
	case MessageTypeKeyGen1, MessageTypeSign1, MessageTypeSign2:
		if h.To != 0 {
			return nil, errors.New("Header.BytesAppend: .To field must be 0 to indicate broadcast")
		}
	case MessageTypeKeyGen2:
		if h.To == 0 {
			return nil, errors.New("Header.BytesAppend: MessageTypeKeyGen2 requires a sender (.To field)")
		}
	default:
		return nil, errors.New("Header.BytesAppend: invalid message type")
	}
	if h.From == 0 {
		return nil, errors.New("Header.BytesAppend: message must include a non 0 From value")
	}
	existing = append(existing, byte(h.Type))
	existing = append(existing, h.From.Bytes()...)
	existing = append(existing, h.To.Bytes()...)
	return existing, nil
}

func (h *Header) Size() int {
	return headerSize
}

func (h *Header) Equal(other interface{}) bool {
	if otherMsg, ok := other.(Header); ok {
		return *h == otherMsg
	}
	if otherMsg, ok := other.(*Header); ok {
		return *h == *otherMsg
	}
	return false
}

// IsBroadcast returns true if the message is intended to be broadcast
func (h *Header) IsBroadcast() bool {
	return h.To == 0
}
