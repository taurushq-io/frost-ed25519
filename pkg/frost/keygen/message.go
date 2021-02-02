package keygen

import (
	"bytes"
	"encoding/binary"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"
	"github.com/taurusgroup/tg-tss/pkg/helpers/zk"
)

type (
	Msg1 struct {
		From		uint32
		Proof 		*zk.Schnorr
		Commitments *polynomial.Exponent
	}

	Msg2 struct {
		From, To uint32
		Share *edwards25519.Scalar
	}
)

const (
	SizeMessage2 = 1 + 4 + 4 + 32
)

// MarshalBinary creates a []byte slice with [MsgType + From + CommitmentD + CommitmentE]
func (m *Msg1) MarshalBinary() (data []byte, err error) {
	if m.Proof == nil || m.Commitments == nil {
		return nil, fmt.Errorf("msg1: %w", frost.ErrInvalidMessage)
	}

	proofBytes, err := m.Proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	commitmentBytes, err := m.Commitments.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 1 + 4 + len(proofBytes) + len(commitmentBytes))
	Buf := bytes.NewBuffer(buf)
	Buf.WriteByte(byte(frost.MessageTypeKeyGen1))
	binary.Write(Buf, binary.BigEndian, m.From)
	Buf.Write(proofBytes)
	Buf.Write(commitmentBytes)

	return Buf.Bytes(), nil
}

func (m *Msg1) Size() int {
	return 1 + 4 + 64 + 32 * m.Commitments.Size()
}

func (m *Msg1) UnmarshalBinary(data []byte) error {
	var err error

	if frost.MessageType(data[0]) != frost.MessageTypeKeyGen1 {
		return frost.ErrBadMessageType
	}
	data = data[1:]

	m.From = binary.BigEndian.Uint32(data[:])
	data = data[4:]

	m.Proof = new(zk.Schnorr)
	err = m.Proof.UnmarshalBinary(data[:64])
	if err != nil {
		return err
	}
	data = data[64:]

	m.Commitments = new(polynomial.Exponent)
	err = m.Commitments.UnmarshalBinary(data[:])
	if err != nil {
		return err
	}

	return nil
}

// MarshalBinary creates a []byte slice with [MsgType + From + CommitmentD + CommitmentE]
func (m *Msg2) MarshalBinary() ([]byte, error) {
	var buf [SizeMessage2]byte

	if m.Share == nil {
		return nil, fmt.Errorf("msg2: %w", frost.ErrInvalidMessage)
	}

	Buf := bytes.NewBuffer(buf[:0])
	Buf.WriteByte(byte(frost.MessageTypeKeyGen2))
	binary.Write(Buf, binary.BigEndian, m.From)
	binary.Write(Buf, binary.BigEndian, m.To)
	Buf.Write(m.Share.Bytes())
	return Buf.Bytes(), nil
}

func (m *Msg2) Size() int {
	return SizeMessage2
}

func (m *Msg2) UnmarshalBinary(data []byte) error {
	var err error

	if len(data) != SizeMessage2 {
		return fmt.Errorf("msg2: %w", frost.ErrInvalidMessage)
	}

	if frost.MessageType(data[0]) != frost.MessageTypeKeyGen2 {
		return fmt.Errorf("msg2: %w", frost.ErrBadMessageType)
	}
	data = data[1:]

	m.From = binary.BigEndian.Uint32(data[:])
	data = data[4:]

	m.To = binary.BigEndian.Uint32(data[:])
	data = data[4:]

	m.Share, err = new(edwards25519.Scalar).SetCanonicalBytes(data)
	if err != nil {
		return err
	}

	return nil
}