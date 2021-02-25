package messages

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/zk"
)

type KeyGen1 struct {
	Proof       *zk.Schnorr
	Commitments *polynomial.Exponent
}

func NewKeyGen1(from uint32, proof *zk.Schnorr, commitments *polynomial.Exponent) *Message {
	return &Message{
		Type: MessageTypeKeyGen1,
		From: from,
		KeyGen1: &KeyGen1{
			Proof:       proof,
			Commitments: commitments,
		},
	}
}

func (m *KeyGen1) BytesAppend(existing []byte) ([]byte, error) {
	var err error

	if m.Proof == nil || m.Commitments == nil {
		return nil, fmt.Errorf("msg1: %w", ErrInvalidMessage)
	}

	existing, err = m.Proof.BytesAppend(existing)
	if err != nil {
		return nil, err
	}
	existing, err = m.Commitments.BytesAppend(existing)
	if err != nil {
		return nil, err
	}
	return existing, nil
}

func (m *KeyGen1) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, m.Size())

	return m.BytesAppend(buf)
}

func (m *KeyGen1) UnmarshalBinary(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("msg1: %w", ErrInvalidMessage)
	}

	var proof zk.Schnorr
	var commitments polynomial.Exponent

	if err := proof.UnmarshalBinary(data[:64]); err != nil {
		return err
	}
	m.Proof = &proof

	if err := commitments.UnmarshalBinary(data[64:]); err != nil {
		return err
	}
	m.Commitments = &commitments
	return nil
}

func (m *KeyGen1) Size() int {
	return m.Proof.Size() + m.Commitments.Size()
}

func (m *KeyGen1) Equal(other interface{}) bool {
	otherMsg, ok := other.(*KeyGen1)
	if !ok {
		return false
	}
	if !otherMsg.Proof.Equal(m.Proof) {
		return false
	}
	if !otherMsg.Commitments.Equal(m.Commitments) {
		return false
	}
	return true
}
