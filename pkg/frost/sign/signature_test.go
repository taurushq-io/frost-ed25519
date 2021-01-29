package sign

import (
	"crypto/ed25519"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"testing"
)

func TestSignatureEncode_Decode(t *testing.T) {
	m := []byte("hello")
	s, _ := common.NewScalarRandom()
	p := new(edwards25519.Point).ScalarBaseMult(s)
	sig := NewSignature(m, s, p)
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
	s, _ := common.NewScalarRandom()
	p := new(edwards25519.Point).ScalarBaseMult(s)
	sig := NewSignature(m, s, p)
	require.True(t, sig.Verify(m, p))
}

func TestSignature_VerifyEd25519(t *testing.T) {
	m := []byte("hello")
	s, _ := common.NewScalarRandom()
	p := new(edwards25519.Point).ScalarBaseMult(s)
	bBytes := p.Bytes()
	sig := NewSignature(m, s, p)
	//sigBin, err := sig.Encode(0)
	//require.NoError(t, err)
	//_, _, c := DecodeBytes(sigBin)
	pk := ed25519.PublicKey(bBytes)

	sigBytes2 := make([]byte, 0, 64)
	sigBytes2 = append(sigBytes2, sig.R.Bytes()...)
	//sigBytes2 = append(sigBytes2, sig.R.BytesMontgomery()...)
	sigBytes2 = append(sigBytes2, sig.S.Bytes()...)

	assert.True(t, ed25519.Verify(pk, m, sigBytes2))
	//assert.True(t, ed25519.Verify(pk, m, c))

}
