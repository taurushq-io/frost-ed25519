package messages

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestSign2_MarshalBinary(t *testing.T) {
	from := rand.Uint32()
	s := scalar.NewScalarRandom()

	msg := NewSign2(from, s)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaller(msg, &msg2))
	require.True(t, msg.Equal(&msg2), "messages are not equal")
}
