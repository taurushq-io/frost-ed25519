package eddsa

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const MessageLengthSig = 32 + 32

var ErrInvalidMessage = errors.New("invalid message")

// Signature represents an EdDSA signature.
// When converted to bytes with .ToEd25519(), the signature is compatible with
// the standard ed25519 library.
type Signature struct {
	R ristretto.Element
	S ristretto.Scalar
}

// ToEd25519 returns a signature that can be validated by ed25519.Verify.
func (sig *Signature) ToEd25519() []byte {
	out := make([]byte, 0, MessageLengthSig)
	out = append(out, sig.R.BytesEd25519()...)
	out = append(out, sig.S.Bytes()...)
	return out
}

// ComputeChallenge computes the value H(R, A, M), and assumes nothing about whether M is hashed.
func ComputeChallenge(R *ristretto.Element, groupKey *PublicKey, message []byte) *ristretto.Scalar {
	var s ristretto.Scalar
	data := make([]byte, 0, 64+len(message))
	data = append(data, R.BytesEd25519()...)
	data = append(data, groupKey.ToEd25519()...)
	data = append(data, message...)
	digest := sha512.Sum512(data)
	_, err := s.SetUniformBytes(digest[:])
	if err != nil {
		panic(err)
	}
	return &s
}

//
// FROSTMarshaler
//

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (sig *Signature) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, MessageLengthSig)
	return sig.BytesAppend(out)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (sig *Signature) UnmarshalBinary(data []byte) error {
	var err error
	if len(data) < MessageLengthSig {
		return fmt.Errorf("sig: %w", ErrInvalidMessage)
	}

	_, err = sig.R.SetCanonicalBytes(data[:32])
	if err != nil {
		return fmt.Errorf("sig.Ri: %w", err)
	}
	_, err = sig.S.SetCanonicalBytes(data[32:])
	if err != nil {
		return fmt.Errorf("sig.S: %w", err)
	}

	return nil
}

func (sig *Signature) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, sig.R.Bytes()...)
	existing = append(existing, sig.S.Bytes()...)
	return existing, nil
}

func (sig *Signature) Size() int {
	return MessageLengthSig
}

func (sig *Signature) Equal(other interface{}) bool {
	otherSignature, ok := other.(*Signature)
	if !ok {
		return false
	}
	if otherSignature.R.Equal(&sig.R) != 1 {
		return false
	}
	if otherSignature.S.Equal(&sig.S) != 1 {
		return false
	}
	return true
}
