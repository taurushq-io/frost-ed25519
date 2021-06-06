package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// PublicKey represents a FROST-Ed25519 verification key.
type PublicKey struct {
	pk ristretto.Element
}

// NewPublicKeyFromPoint returns a PublicKey given an ristretto.Element.
func NewPublicKeyFromPoint(public *ristretto.Element) *PublicKey {
	var pk PublicKey
	pk.pk.Set(public)
	return &pk
}

func (pk *PublicKey) Verify(message []byte, sig *Signature) bool {
	challenge := ComputeChallenge(&sig.R, pk, message)

	// Verify the full signature here too.
	var publicNeg, RPrime ristretto.Element
	publicNeg.Negate(&pk.pk)
	// RPrime = [c](-A) + [s]B
	RPrime.VarTimeDoubleScalarBaseMult(challenge, &publicNeg, &sig.S)
	return RPrime.Equal(&sig.R) == 1
}

// Equal returns true if the public key is equal to pk0
func (pk *PublicKey) Equal(pkOther *PublicKey) bool {
	return pk.pk.Equal(&pkOther.pk) == 1
}

// ToEd25519 converts the PublicKey to an ed25519 compatible format
func (pk *PublicKey) ToEd25519() ed25519.PublicKey {
	return pk.pk.BytesEd25519()
}

func newKeyPair(key ed25519.PrivateKey) (*ristretto.Scalar, *PublicKey) {
	var (
		sk ristretto.Scalar
		pk PublicKey
	)
	digest := sha512.Sum512(key[:32])

	_, _ = sk.SetBytesWithClamping(digest[:32])
	pk.pk.ScalarBaseMult(&sk)

	return &sk, &pk
}

// MarshalJSON implements the json.Marshaler interface.
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&pk.pk)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (pk *PublicKey) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &pk.pk)
}
