package frost

import (
	"encoding/binary"
	"errors"
)

type MessageType uint8

var ErrInvalidMessage = errors.New("invalid message")

const (
	MessageTypeSign1 MessageType = iota
	MessageTypeSign2
	MessageTypeSignature
)

const HeaderLength = 4 + 1

func DecodeBytes(in []byte) (from uint32, msgType MessageType, content []byte) {
	msgType = MessageType(in[0])
	from = binary.BigEndian.Uint32(in[1:])
	content = in[5:]
	return
}
