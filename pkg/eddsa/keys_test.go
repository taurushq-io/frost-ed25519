package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
)

func TestPrivateKey_ToEd25519(t *testing.T) {
	pkbytes, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err, "failed to generate key")

	sk, pk := newKeyPair(skBytes)
	assert.NoError(t, err, "failed to create key pair")

	pkOther, err := newPublicKey(pkbytes)
	assert.NoError(t, err, "failed to create public key")

	pkComputed := edwards25519.NewIdentityPoint().ScalarBaseMult(sk)
	assert.Equal(t, 1, pk.Point().Equal(pkComputed))

	assert.True(t, pkOther.Equal(pk))

	pkFromSk := new(edwards25519.Point).ScalarBaseMult(sk)
	assert.Equal(t, 1, pk.Point().Equal(pkFromSk))
}
