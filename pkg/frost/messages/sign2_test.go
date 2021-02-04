package messages

import (
	"bytes"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"math/rand"
	"testing"
)

func TestSign2_MarshalBinary(t *testing.T) {
	var s *edwards25519.Scalar
	var err error

	from := rand.Uint32()
	s = common.NewScalarRandom()

	msg := NewSign2(from, s)

	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	msgDec := new(Message)
	err = msgDec.UnmarshalBinary(msgBytes)
	require.NoError(t, err, "unmarshalling failed")

	msgDecBytes, err := msgDec.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	assert.True(t, bytes.Equal(msgBytes, msgDecBytes), "unmarshal -> marshal should give the same result")

	require.NotNil(t, msgDec.Sign2, "sign2 is nil")
	require.NotNil(t, msgDec.Sign2.Zi, "s is nil")

	assert.Equal(t, 1, s.Equal(&msgDec.Sign2.Zi), "s are not equal")
	assert.Equal(t, msg.From, msgDec.From, "from is not the same")
	assert.Equal(t, MessageTypeSign2, msgDec.Type, "type is wrong")
}
