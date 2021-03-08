package eddsa

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

const MessageLengthSig = 32 + 32

var ErrInvalidMessage = errors.New("invalid message")

// Signature represents an EdDSA signature.
// When converted to bytes with .ToEd25519(), the signature is compatible with
// the standard ed25519 library.
type Signature struct {
	R edwards25519.Point
	S edwards25519.Scalar
}

func Verify(c, s *edwards25519.Scalar, public *PublicKey, R *edwards25519.Point) bool {
	var publicNeg, RPrime edwards25519.Point
	publicNeg.Negate(public.Point())

	// RPrime = [8](R - (-[c]A + [s]B))
	RPrime.VarTimeDoubleScalarBaseMult(c, &publicNeg, s)
	RPrime.Negate(&RPrime)
	RPrime.Add(&RPrime, R)
	RPrime.MultByCofactor(&RPrime)
	return RPrime.Equal(edwards25519.NewIdentityPoint()) == 1
}

// Verify checks that the signature is valid
func (s *Signature) Verify(message []byte, publicKey *PublicKey) bool {
	k := ComputeChallenge(&s.R, publicKey, message)

	return Verify(k, &s.S, publicKey, &s.R)
}

// ToEd25519 returns a signature that can be validated by ed25519.Verify.
func (s *Signature) ToEd25519() []byte {
	var sig [64]byte
	copy(sig[:32], s.R.Bytes())
	copy(sig[32:], s.S.Bytes())
	return sig[:]
}

// ComputeChallenge computes the value H(R, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(R *edwards25519.Point, groupKey *PublicKey, message []byte) *edwards25519.Scalar {
	var s edwards25519.Scalar

	data := make([]byte, 0, 64+len(message))
	data = append(data, R.Bytes()...)
	data = append(data, groupKey.Point().Bytes()...)
	data = append(data, message...)
	digest := sha512.Sum512(data)
	s.SetUniformBytes(digest[:])

	return &s
}

//
// FROSTMarshaller
//

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (s *Signature) MarshalBinary() ([]byte, error) {
	return s.ToEd25519(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
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
	return append(existing, s.ToEd25519()...), nil
}

func (s *Signature) Size() int {
	return MessageLengthSig
}

func (s *Signature) Equal(other interface{}) bool {
	otherSignature, ok := other.(*Signature)
	if !ok {
		return false
	}
	if otherSignature.R.Equal(&s.R) != 1 {
		return false
	}
	if otherSignature.S.Equal(&s.S) != 1 {
		return false
	}
	return true
}
