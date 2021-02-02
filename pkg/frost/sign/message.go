package sign

import (
	"bytes"
	"encoding/binary"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/frost"
)

const (
	MessageLength1   = 32 + 32
	MessageLength2   = 32
)
type (
	Msg1 struct {
		// CommitmentD and CommitmentE are edwards25519.Point encoded with .... TODO
		CommitmentD, CommitmentE *edwards25519.Point
	}

	Msg2 struct {
		// SignatureShare is a edwards25519.Scalar.
		// It represents the sender's share of the 's' part of the final signature
		SignatureShare *edwards25519.Scalar
	}
)

// Encode creates a []byte slice with [MsgType + From + CommitmentD + CommitmentE]
func (m *Msg1) Encode(from uint32) ([]byte, error) {
	if m.CommitmentD == nil || m.CommitmentE == nil {
		return nil, fmt.Errorf("msg1: %w", frost.ErrInvalidMessage)
	}
	buf := make([]byte, 0, frost.HeaderLength+MessageLength1)
	Buf := bytes.NewBuffer(buf)
	Buf.Write([]byte{byte(frost.MessageTypeSign1)})
	binary.Write(Buf, binary.BigEndian, from)
	Buf.Write(m.CommitmentD.Bytes())
	Buf.Write(m.CommitmentE.Bytes())
	return Buf.Bytes(), nil
}

func (m *Msg1) Decode(in []byte) (*Msg1, error) {
	var err error

	if len(in) != MessageLength1 {
		m = nil
		return nil, fmt.Errorf("msg1: %w", frost.ErrInvalidMessage)
	}
	m.CommitmentD, err = new(edwards25519.Point).SetBytes(in[:32])
	if err != nil {
		m = nil
		return nil, fmt.Errorf("msg1.D: %w", err)
	}

	m.CommitmentE, err = new(edwards25519.Point).SetBytes(in[32:])
	if err != nil {
		m = nil
		return nil, fmt.Errorf("msg1.E: %w", err)
	}

	return m, nil
}

// Encode creates a []byte slice with [MsgType + From + SignatureShare]
func (m *Msg2) Encode(from uint32) ([]byte, error) {
	if m.SignatureShare == nil {
		return nil, fmt.Errorf("msg2: %w", frost.ErrInvalidMessage)
	}
	buf := make([]byte, 0, frost.HeaderLength+MessageLength2)
	Buf := bytes.NewBuffer(buf)
	Buf.Write([]byte{byte(frost.MessageTypeSign2)})
	binary.Write(Buf, binary.BigEndian, from)
	Buf.Write(m.SignatureShare.Bytes())
	return Buf.Bytes(), nil
}

func (m *Msg2) Decode(in []byte) (*Msg2, error) {
	var err error
	if len(in) != MessageLength2 {
		m = nil
		return nil, fmt.Errorf("msg2: %w", frost.ErrInvalidMessage)
	}
	m.SignatureShare, err = new(edwards25519.Scalar).SetCanonicalBytes(in[:32])
	if err != nil {
		m = nil
		return nil, fmt.Errorf("msg2.SigShare: %w", err)
	}

	return m, nil
}
