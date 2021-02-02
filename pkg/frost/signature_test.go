package frost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	//"github.com/taurusgroup/tg-tss/pkg/frost/sign"
	"testing"
)

func TestSignatureEncode_Decode(t *testing.T) {
	m := []byte("hello")
	_, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	sk := NewPrivateKey(skBytes)
	pk := sk.PublicKey()

	sig := NewSignature(m, sk, pk)
	fromReal := uint32(42)
	sigBytes, err := sig.Encode(fromReal)
	assert.NoError(t, err)
	from, msgType, c := DecodeBytes(sigBytes)
	assert.Equal(t, MessageTypeSignature, msgType)
	assert.Equal(t, fromReal, from, "from not decoded")

	sig2, err := new(Signature).Decode(c)

	assert.NoError(t, err)
	assert.Equal(t, 1, sig.R.Equal(sig2.R))
	assert.Equal(t, 1, sig.S.Equal(sig2.S))
}

func TestSignature_Verify(t *testing.T) {
	m := []byte("hello")
	_, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	sk := NewPrivateKey(skBytes)
	pk := sk.PublicKey()

	sig := NewSignature(m, sk, pk)
	require.True(t, sig.Verify(m, pk))
}

func TestSignature_VerifyEd25519(t *testing.T) {

	pkBytes, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	sk := NewPrivateKey(skBytes)
	pk := sk.PublicKey()

	assert.True(t, bytes.Equal(pk.Point().Bytes(), pkBytes))

	pkComp := new(edwards25519.Point).ScalarBaseMult(sk.Scalar())
	assert.Equal(t, 1, pk.Point().Equal(pkComp))

	m := []byte("hello")
	hm := ComputeMessageHash(m)
	sig := NewSignature(hm, sk, pk)
	sigEdDSA := sig.ToEdDSA()

	assert.True(t, ed25519.Verify(pkBytes, hm, sigEdDSA))
}
