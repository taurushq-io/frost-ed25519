package frost

import (
	"crypto/ed25519"
	"crypto/sha512"
	"filippo.io/edwards25519"
)

type PublicKey struct {
	pk edwards25519.Point
}

func NewPublicKey(key ed25519.PublicKey) (*PublicKey, error) {
	pk := new(PublicKey)
	_, err := pk.pk.SetBytes(key)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func (pk *PublicKey) Point() *edwards25519.Point {
	return &pk.pk
}

func (pk *PublicKey) ToEdDSA() ed25519.PublicKey {
	var key [32]byte
	copy(key[:], pk.pk.Bytes())
	return key[:]
}

// PrivateKey is created from an ed25519.PrivateKey and remembers the seed
// in order to go back to that format
type PrivateKey struct {
	sk   edwards25519.Scalar
	pk   *PublicKey
	seed [32]byte
}

func NewPrivateKey(key ed25519.PrivateKey) *PrivateKey {
	sk := new(PrivateKey)
	copy(sk.seed[:], key[:32])
	h := sha512.New()
	h.Write(key[:32])
	digest := h.Sum(nil)
	sk.sk.SetBytesWithClamping(digest[:32])

	sk.pk = new(PublicKey)
	sk.pk.pk.ScalarBaseMult(sk.Scalar())
	return sk
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}

func (sk *PrivateKey) ToEdDSA() ed25519.PrivateKey {
	var key [64]byte
	copy(key[0:], sk.seed[0:])
	copy(key[32:], sk.pk.Point().Bytes())
	return key[:]
}

func (sk *PrivateKey) Scalar() *edwards25519.Scalar {
	return &sk.sk
}
