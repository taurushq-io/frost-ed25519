package eddsa

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

const MessageLengthSig = 32 + 32

var ErrInvalidMessage = errors.New("invalid message")

type Signature struct {
	R edwards25519.Point
	S edwards25519.Scalar
}

func NewSignature(message []byte, secretKey *PrivateKey, publicKey *PublicKey) *Signature {
	var sig Signature

	r := scalar.NewScalarRandom()

	// R = [r] • B
	sig.R.ScalarBaseMult(r)

	// C = H(R, A, M)
	c := ComputeChallenge(&sig.R, publicKey.Point(), message)
	sig.S.Multiply(secretKey.Scalar(), c)
	sig.S.Add(&sig.S, r)

	return &sig
}

// Verify checks that the signature is valid
func (s *Signature) Verify(message []byte, publicKey *PublicKey) bool {
	var RPrime edwards25519.Point

	k := ComputeChallenge(&s.R, publicKey.Point(), message)
	k.Negate(k)
	// RPrime = [-l]A + [s]B
	RPrime.VarTimeDoubleScalarBaseMult(k, publicKey.Point(), &s.S)

	return RPrime.Equal(&s.R) == 1
}

// ToEdDSA returns a signature that can be validated by ed25519.Verify.
func (s *Signature) ToEdDSA() []byte {
	var sig [64]byte
	copy(sig[:32], s.R.Bytes())
	copy(sig[32:], s.S.Bytes())
	return sig[:]
}

//
// FROSTMarshaller
//

func (s *Signature) MarshalBinary() ([]byte, error) {
	return s.ToEdDSA(), nil
}

func (s *Signature) UnmarshalBinary(data []byte) error {
	var err error
	if len(data) != MessageLengthSig {
		return fmt.Errorf("sig: %w", ErrInvalidMessage)
	}
	_, err = s.R.SetBytes(data[:32])
	if err != nil {
		return fmt.Errorf("sig.Ri: %w", err)
	}
	_, err = s.S.SetCanonicalBytes(data[32:])
	if err != nil {
		return fmt.Errorf("sig.S: %w", err)
	}

	return nil
}

func (s *Signature) BytesAppend(existing []byte) ([]byte, error) {
	return append(existing, s.ToEdDSA()...), nil
}

func (s *Signature) Size() int {
	return MessageLengthSig
}
