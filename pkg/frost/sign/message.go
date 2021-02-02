package sign

import (
	"bytes"
	"encoding/binary"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/frost"
)

const (
	MessageLength1   = 1 + 4 + 32 + 32
	MessageLength2   = 1 + 4 + 32
)
type (
	Msg1 struct {
		From uint32
		// CommitmentD and CommitmentE are edwards25519.Point encoded with .... TODO
		CommitmentD, CommitmentE *edwards25519.Point
	}

	Msg2 struct {
		From uint32
		// SignatureShare is a edwards25519.Scalar.
		// It represents the sender's share of the 's' part of the final signature
		SignatureShare *edwards25519.Scalar
	}
)

// Encode creates a []byte slice with [MsgType + From + CommitmentD + CommitmentE]
func (m *Msg1) MarshalBinary() ([]byte, error) {
	var buf [MessageLength1]byte
	if m.CommitmentD == nil || m.CommitmentE == nil {
		return nil, fmt.Errorf("msg1: %w", frost.ErrInvalidMessage)
	}
	Buf := bytes.NewBuffer(buf[:0])
	Buf.WriteByte(byte(frost.MessageTypeSign1))
	binary.Write(Buf, binary.BigEndian, m.From)
	Buf.Write(m.CommitmentD.Bytes())
	Buf.Write(m.CommitmentE.Bytes())
	return Buf.Bytes(), nil
}

func (m *Msg1) UnmarshalBinary(data []byte) error {
	var err error

	if len(data) != MessageLength1 {
		return fmt.Errorf("msg1: %w", frost.ErrInvalidMessage)
	}

	if frost.MessageType(data[0]) != frost.MessageTypeSign1 {
		return frost.ErrBadMessageType
	}
	data = data[1:]

	m.From = binary.BigEndian.Uint32(data[:])
	data = data[4:]

	m.CommitmentD, err = new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return fmt.Errorf("msg1.D: %w", err)
	}
	data = data[32:]

	m.CommitmentE, err = new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return fmt.Errorf("msg1.E: %w", err)
	}

	return nil
}

// Encode creates a []byte slice with [MsgType + From + SignatureShare]
func (m *Msg2) MarshalBinary() ([]byte, error) {
	var buf [MessageLength2]byte
	if m.SignatureShare == nil {
		return nil, fmt.Errorf("msg2: %w", frost.ErrInvalidMessage)
	}

	Buf := bytes.NewBuffer(buf[:0])
	Buf.WriteByte(byte(frost.MessageTypeSign2))
	binary.Write(Buf, binary.BigEndian, m.From)
	Buf.Write(m.SignatureShare.Bytes())
	return Buf.Bytes(), nil
}

func (m *Msg2) UnmarshalBinary(data []byte) error {
	var err error
	if len(data) != MessageLength2 {
		return fmt.Errorf("msg2: %w", frost.ErrInvalidMessage)
	}

	if frost.MessageType(data[0]) != frost.MessageTypeSign2 {
		return frost.ErrBadMessageType
	}
	data = data[1:]

	m.From = binary.BigEndian.Uint32(data[:])
	data = data[4:]

	m.SignatureShare, err = new(edwards25519.Scalar).SetCanonicalBytes(data[:32])
	if err != nil {
		return fmt.Errorf("msg2.SigShare: %w", err)
	}

	return nil
}
