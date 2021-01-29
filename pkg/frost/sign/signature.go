package sign

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

type Signature struct {
	R *edwards25519.Point
	S *edwards25519.Scalar
}

func (s *Signature) Verify(message []byte, publicKey *edwards25519.Point) bool {

	k := ComputeChallenge(message, publicKey, s.R)

	lhs := new(edwards25519.Point).ScalarBaseMult(s.S)
	lhs.MultByCofactor(lhs)

	rhs := new(edwards25519.Point).ScalarMult(k, publicKey)
	rhs.Add(rhs, s.R)
	rhs.MultByCofactor(rhs)

	return lhs.Equal(rhs) == 1
}

func (s *Signature) Encode(from uint32) ([]byte, error) {
	if s.S == nil || s.R == nil {
		return nil, fmt.Errorf("sig: %w", ErrInvalidMessage)
	}
	buf := make([]byte, 0, HeaderLength+MessageLengthSig)
	Buf := bytes.NewBuffer(buf)
	Buf.Write([]byte{byte(MessageTypeSignature)})
	binary.Write(Buf, binary.BigEndian, from)
	Buf.Write(s.R.Bytes())
	Buf.Write(s.S.Bytes())
	return Buf.Bytes(), nil
}

func (s *Signature) Decode(in []byte) (*Signature, error) {
	var err error
	if len(in) != MessageLengthSig {
		s = nil
		return nil, fmt.Errorf("sig: %w", ErrInvalidMessage)
	}
	s.R, err = new(edwards25519.Point).SetBytes(in[:32])
	if err != nil {
		s = nil
		return nil, fmt.Errorf("sig.R: %w", err)
	}
	s.S, err = new(edwards25519.Scalar).SetCanonicalBytes(in[32:])
	if err != nil {
		s = nil
		return nil, fmt.Errorf("sig.S: %w", err)
	}

	return s, nil
}

// Compute the SHA 512 of the message
func ComputeMessageHash(context []byte, message []byte) []byte {
	h := sha512.New()
	h.Write(context)
	h.Write(message)
	out := h.Sum(nil)
	return out
}

func ComputeChallenge(messageHash []byte, groupKey, R *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(R.Bytes())
	h.Write(groupKey.Bytes())
	h.Write(messageHash)

	k := edwards25519.NewScalar()
	k.SetUniformBytes(h.Sum(nil))
	return k
}

func NewSignature(message []byte, secretKey *edwards25519.Scalar, publicKey *edwards25519.Point) *Signature {
	hashedM := ComputeMessageHash(nil, message)
	r, _ := common.NewScalarRandom()
	R := new(edwards25519.Point).ScalarBaseMult(r)
	c := ComputeChallenge(hashedM, publicKey, R)
	s := new(edwards25519.Scalar).Multiply(secretKey, c)
	s.Add(s, r)
	return &Signature{
		R: R,
		S: s,
	}
}
