package frost

import (
	"encoding/binary"
	"errors"
)

type MessageType uint8

var (
	ErrInvalidMessage = errors.New("invalid message")
	ErrBadMessageType = errors.New("message type is wrong")
)


const (
	MessageTypeKeyGen1 MessageType = iota
	MessageTypeKeyGen2
	MessageTypeSign1
	MessageTypeSign2
	MessageTypeSignature
)

const HeaderLength = 4 + 1

func DecodeBytes(in []byte) (msgType MessageType, from uint32) {
	msgType = MessageType(in[0])
	from = binary.BigEndian.Uint32(in[1:])
	return
}
