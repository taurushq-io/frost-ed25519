package messages

import (
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

const SignSizeOutput = 64

type SignOutput struct {
	eddsa.Signature
}

func NewSignOutput(R *edwards25519.Point, s *edwards25519.Scalar) *Message {
	var msg SignOutput

	msg.R.Set(R)
	msg.S.Set(s)

	return &Message{
		Type:       MessageTypeSignOutput,
		SignOutput: &msg,
	}
}

func (m *SignOutput) BytesAppend(existing []byte) ([]byte, error) {
	return m.Signature.BytesAppend(existing)
}

// Encode creates a []byte slice with [MsgType + From + Di + Ei]
func (m *SignOutput) MarshalBinary() ([]byte, error) {
	var buf [SignSizeOutput]byte
	return m.Signature.BytesAppend(buf[:0])
}

func (m *SignOutput) UnmarshalBinary(data []byte) error {
	if len(data) != SignSizeOutput {
		return fmt.Errorf("msg3: %w", ErrInvalidMessage)
	}

	return m.Signature.UnmarshalBinary(data)
}

func (m *SignOutput) Size() int {
	return SignSizeOutput
}
