package messages

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

type PreSignRequest struct {
	x bool
}

func NewPreSignRequest(from party.ID) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeSign1,
			From: from,
		},
	}
}

func (m *PreSignRequest) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, 1)
	return existing, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *PreSignRequest) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 1)
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *PreSignRequest) UnmarshalBinary(data []byte) error {
	m = &PreSignRequest{x: true}
	return nil
}

func (m *PreSignRequest) Size() int {
	return 1
}

func (m *PreSignRequest) Equal(other interface{}) bool {
	return true
}
