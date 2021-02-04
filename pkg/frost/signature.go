package frost

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

const MessageLengthSig = 32 + 32

var ErrInvalidMessage = errors.New("invalid message")

type Signature struct {
	R edwards25519.Point
	S edwards25519.Scalar
}

func NewSignature(message []byte, secretKey *PrivateKey, publicKey *PublicKey) *Signature {
	sig := new(Signature)
	r := common.NewScalarRandom()
	sig.R.ScalarBaseMult(r)
	c := ComputeChallenge(message, publicKey, &sig.R)
	sig.S.Multiply(secretKey.Scalar(), c)
	sig.S.Add(&sig.S, r)
	return sig
}

func (s *Signature) Verify(message []byte, publicKey *PublicKey) bool {
	var RPrime, ANeg edwards25519.Point
	k := ComputeChallenge(message, publicKey, &s.R)
	ANeg.Negate(publicKey.Point())
	// RPrime = [-l]A + [s]B
	RPrime.VarTimeDoubleScalarBaseMult(k, &ANeg, &s.S)

	return RPrime.Equal(&s.R) == 1
}

func (s *Signature) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, s.R.Bytes()...)
	existing = append(existing, s.S.Bytes()...)
	return existing, nil
}

func (s *Signature) MarshalBinary() ([]byte, error) {
	var buf [MessageLengthSig]byte
	return s.BytesAppend(buf[:0])
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

func (s *Signature) Size() int {
	return MessageLengthSig
}

// Compute the SHA 512 of the message
func ComputeMessageHash(message []byte) []byte {
	var out [64]byte
	h := sha512.New()
	h.Write(message)
	h.Sum(out[:0])
	return out[:]
}

// ComputeChallenge computes the value H(Ri, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(message []byte, groupKey *PublicKey, R *edwards25519.Point) *edwards25519.Scalar {
	var kHash [64]byte
	var k edwards25519.Scalar

	h := sha512.New()
	h.Write(R.Bytes())
	h.Write(groupKey.Point().Bytes())
	h.Write(message)
	h.Sum(kHash[:0])
	k.SetUniformBytes(kHash[:])
	return &k
}
