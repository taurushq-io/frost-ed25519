package frost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

const MessageLengthSig = 1 + 4 + 32 + 32

type Signature struct {
	R *edwards25519.Point
	S *edwards25519.Scalar
}

func NewSignature(message []byte, secretKey *PrivateKey, publicKey *PublicKey) *Signature {
	r := common.NewScalarRandom()
	R := new(edwards25519.Point).ScalarBaseMult(r)
	c := ComputeChallenge(message, publicKey, R)
	s := new(edwards25519.Scalar).Multiply(secretKey.Scalar(), c)
	s.Add(s, r)
	return &Signature{
		R: R,
		S: s,
	}
}

func (s *Signature) Verify(message []byte, publicKey *PublicKey) bool {
	k := ComputeChallenge(message, publicKey, s.R)
	k.Negate(k)

	// RPrime = [-l]A + [s]B
	RPrime := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, publicKey.Point(), s.S)

	return RPrime.Equal(s.R) == 1
}

func (s *Signature) MarshalBinary() ([]byte, error)  {
	if s.S == nil || s.R == nil {
		return nil, fmt.Errorf("sig: %w", ErrInvalidMessage)
	}
	buf := make([]byte, 0, HeaderLength+MessageLengthSig)
	Buf := bytes.NewBuffer(buf)
	Buf.Write([]byte{byte(MessageTypeSignature)})
	binary.Write(Buf, binary.BigEndian, uint32(3))
	Buf.Write(s.ToEdDSA())
	return Buf.Bytes(), nil
}

func (s *Signature) UnmarshalBinary(data []byte) error {
	var err error
	if len(data) != MessageLengthSig {
		return fmt.Errorf("sig: %w", ErrInvalidMessage)
	}
	data = data[5:]
	s.R, err = new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return fmt.Errorf("sig.R: %w", err)
	}
	s.S, err = new(edwards25519.Scalar).SetCanonicalBytes(data[32:])
	if err != nil {
		return fmt.Errorf("sig.S: %w", err)
	}

	return nil
}

// Compute the SHA 512 of the message
func ComputeMessageHash(message []byte) []byte {
	h := sha512.New()
	h.Write(message)
	out := h.Sum(nil)
	return out
}

// ComputeChallenge computes the value H(R, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(message []byte, groupKey *PublicKey, R *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(R.Bytes())
	h.Write(groupKey.Point().Bytes())
	h.Write(message)

	k := edwards25519.NewScalar()
	k.SetUniformBytes(h.Sum(nil))
	return k
}

func (s *Signature) ToEdDSA() []byte {
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig[0:32], s.R.Bytes())
	copy(sig[32:], s.S.Bytes())
	return sig
}
