package messages

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
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

	msg := NewSignOutput(R, S)
	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err)

	msgDec := new(Message)
	err = msgDec.UnmarshalBinary(msgBytes)

	sigBytes, err := msgDec.SignOutput.MarshalBinary()
	require.NoError(t, err)
	require.True(t, bytes.Equal(sig, sigBytes), "marshalled signature should be the same as the original one")

	require.True(t, ed25519.Verify(pk, message, sigBytes), "marshalled signature should verify")
}
