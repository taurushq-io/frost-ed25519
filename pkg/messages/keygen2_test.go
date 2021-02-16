package messages

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestKeyGen2_MarshalBinary(t *testing.T) {
	from := rand.Uint32()
	to := rand.Uint32()
	secret := scalar.NewScalarRandom()

	msg := NewKeyGen2(from, to, secret)

	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	msgDec := new(Message)
	err = msgDec.UnmarshalBinary(msgBytes)
	require.NoError(t, err, "unmarshalling failed")

	msgDecBytes, err := msgDec.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	assert.True(t, bytes.Equal(msgBytes, msgDecBytes), "unmarshal -> marshal should give the same result")

	require.NotNil(t, msgDec.KeyGen2, "keygen2 is nil")
	require.NotNil(t, msgDec.KeyGen2.Share, "share is nil")

	assert.True(t, msgDec.KeyGen2.Share.Equal(secret) == 1, "shares are not equal")
	assert.Equal(t, msg.From, msgDec.From, "from is not the same")
	assert.Equal(t, MessageTypeKeyGen2, msgDec.Type, "type is wrong")
}
