package eddsa

import (
	"crypto/rand"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

const MessageLengthSig = 32 + 32

var ErrInvalidMessage = errors.New("invalid message")

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

// ToEdDSA returns a signature that can be validated by ed25519.Verify.
func (s *Signature) ToEdDSA() []byte {
	var sig [64]byte
	copy(sig[:32], s.R.Bytes())
	copy(sig[32:], s.S.Bytes())
	return sig[:]
}

func newSignature(message []byte, secretKey *edwards25519.Scalar) *Signature {
	var sig Signature

	var (
		r              edwards25519.Scalar
		publicKeyPoint edwards25519.Point
		rBytes         [64]byte
	)

	if _, err := rand.Reader.Read(rBytes[:]); err != nil {
		panic(fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err))
	}
	r.SetUniformBytes(rBytes[:])

	// R = [r] • B
	sig.R.ScalarBaseMult(&r)

	// C = H(R, A, M)
	publicKeyPoint.ScalarBaseMult(secretKey)
	publicKey := NewPublicKeyFromPoint(&publicKeyPoint)
	c := ComputeChallenge(&sig.R, publicKey, message)

	// S = sk * c + r
	sig.S.Multiply(secretKey, c)
	sig.S.Add(&sig.S, &r)

	return &sig
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
