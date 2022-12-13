package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type Nonce struct {
	PartyID party.ID
	Di      ristretto.Element
	Ei      ristretto.Element
}

type SignRequest struct {
	Msg []byte
	// Di = [di] B
	// Ei = [ei] B
	Nonces []*Nonce
}

func NewSignRequest(from party.ID, msg []byte, nonces []*Nonce) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeSignRequest,
			From: from,
		},
		SignRequest: &SignRequest{
			Msg:    msg,
			Nonces: nonces,
		},
	}
}

func (m *SignRequest) BytesAppend(existing []byte) ([]byte, error) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(m.Msg)))
	existing = append(existing, tmp...)
	existing = append(existing, m.Msg...)
	for i := 0; i < len(m.Nonces); i++ {
		existing = append(existing, m.Nonces[i].PartyID.Bytes()...)
		existing = append(existing, m.Nonces[i].Di.Bytes()...)
		existing = append(existing, m.Nonces[i].Ei.Bytes()...)
	}
	return existing, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *SignRequest) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, sizeSign1)
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *SignRequest) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("sig request less than 4 bytes")
	}

	length := binary.BigEndian.Uint32(data)

	if len(data) < int(4+length) {
		return fmt.Errorf("sig request less msg length")
	}

	m.Msg = data[4 : 4+length]

	if (len(data)-int(length+4))%66 != 0 {
		return fmt.Errorf("not an whole number of nonces left")
	}

	idx := 0
	for i := int(4 + length); i < len(data); i += 66 {
		m.Nonces = append(m.Nonces, &Nonce{})
		id, err := party.FromBytes(data[i:])
		if err != nil {
			return fmt.Errorf("signRequest.partyID: %w", err)
		}

		m.Nonces[idx].PartyID = id

		_, err = m.Nonces[idx].Di.SetCanonicalBytes(data[i+party.IDByteSize : i+party.IDByteSize+32])
		if err != nil {
			return fmt.Errorf("signRequest.D: %w", err)
		}

		_, err = m.Nonces[idx].Ei.SetCanonicalBytes(data[i+party.IDByteSize+32 : i+party.IDByteSize+64])
		if err != nil {
			return fmt.Errorf("signRequest.E: %w", err)
		}
		idx++
	}

	return nil
}

func (m *SignRequest) Size() int {
	return len(m.Msg) + 66*len(m.Nonces)
}

func (m *SignRequest) Equal(other interface{}) bool {
	otherMsg, ok := other.(*SignRequest)
	if !ok {
		return false
	}

	if bytes.Equal(m.Msg, otherMsg.Msg) {
		return false
	}

	if len(m.Nonces) == len(otherMsg.Nonces) {
		return false
	}

	for i := 0; i < len(m.Nonces); i++ {
		if otherMsg.Nonces[i].PartyID.Scalar().Equal(otherMsg.Nonces[i].PartyID.Scalar()) != 1 {
			return false
		}
		if otherMsg.Nonces[i].Di.Equal(&m.Nonces[i].Di) != 1 {
			return false
		}
		if otherMsg.Nonces[i].Ei.Equal(&m.Nonces[i].Ei) != 1 {
			return false
		}
	}
	return true
}
