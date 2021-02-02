package frost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrivateKey_ToEdDSA(t *testing.T) {
	pkBytes, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err, "failed to generate key")

	sk := NewPrivateKey(skBytes)
	pk, err := NewPublicKey(pkBytes)
	assert.NoError(t, err, "failed to create public key")

	skBytesComputed := sk.ToEdDSA()

	assert.True(t, bytes.Equal(skBytes, skBytesComputed), "secret key bytes are not equal")

	pkComputed := new(edwards25519.Point).ScalarBaseMult(sk.Scalar())
	assert.Equal(t, 1, pk.Point().Equal(pkComputed))

	assert.Equal(t, 1, pk.Point().Equal(sk.PublicKey().Point()))
}
