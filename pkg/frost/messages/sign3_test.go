package messages

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSign3_MarshalBinary(t *testing.T) {
	var err error

	message := []byte("hello")
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig, err := sk.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(pk, message, sig))

	R, err := edwards25519.NewIdentityPoint().SetBytes(sig[:32])
	require.NoError(t, err)
	S, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	require.NoError(t, err)

	msg := NewSign3(R, S)
	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err)

	msgDec := new(Message)
	err = msgDec.UnmarshalBinary(msgBytes)

	require.True(t, bytes.Equal(sig, msgDec.Sign3.Sig[:]))
	require.True(t, ed25519.Verify(pk, message, msgDec.Sign3.Sig[:]))
}
