package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

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

func TestPrivateKey_ToEd25519(t *testing.T) {
	pkbytes, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err, "failed to generate key")

	sk, pk := newKeyPair(skBytes)
	assert.NoError(t, err, "failed to create key pair")

	pkComputed := ristretto.NewIdentityElement().ScalarBaseMult(sk)
	assert.Equal(t, 1, pk.pk.Equal(pkComputed))

	pkFromSk := ristretto.NewIdentityElement().ScalarBaseMult(sk)
	assert.Equal(t, 1, pk.pk.Equal(pkFromSk))

	assert.Equal(t, pk.ToEd25519(), pkbytes)
}
