package messages

import (
	"bytes"
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestSign1_MarshalBinary(t *testing.T) {
	from := rand.Uint32()

	var d, e *edwards25519.Scalar
	var D, E *edwards25519.Point

	d = scalar.NewScalarRandom()
	e = scalar.NewScalarRandom()
	D = new(edwards25519.Point).ScalarBaseMult(d)
	E = new(edwards25519.Point).ScalarBaseMult(e)

	msg := NewSign1(from, D, E)

	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	msgDec := new(Message)
	err = msgDec.UnmarshalBinary(msgBytes)
	require.NoError(t, err, "unmarshalling failed")

	msgDecBytes, err := msgDec.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	assert.True(t, bytes.Equal(msgBytes, msgDecBytes), "unmarshal -> marshal should give the same result")

	require.NotNil(t, msgDec.Sign1, "keygen2 is nil")
	require.NotNil(t, msgDec.Sign1.Di, "D is nil")
	require.NotNil(t, msgDec.Sign1.Ei, "E is nil")

	assert.Equal(t, 1, D.Equal(&msgDec.Sign1.Di), "D are not equal")
	assert.Equal(t, 1, E.Equal(&msgDec.Sign1.Ei), "E are not equal")
	assert.Equal(t, msg.From, msgDec.From, "from is not the same")
	assert.Equal(t, MessageTypeSign1, msgDec.Type, "type is wrong")
}
