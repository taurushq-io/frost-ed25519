package frost

import (
	"filippo.io/edwards25519"
	"crypto/sha512"
)

type Signature struct {
	R *edwards25519.Point
	S *edwards25519.Scalar
}

func (s *Signature) Verify(message []byte, publicKey *edwards25519.Point) bool {
	// TODO what about cofactors here ?

	k := ComputeChallenge(message, publicKey, s.R)
	ANeg := new(edwards25519.Point).Negate(publicKey)

	// [s]B - [k]A ==? R
	rhs := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, ANeg, s.S)

	return s.R.Equal(rhs) == 1
}

func (s *Signature) Bytes() []byte {
	b := make([]byte,0, 64)
	b = append(b, s.R.Bytes()...)
	b = append(b, s.S.Bytes()...)
	return b
}

// Compute the SHA 512
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


