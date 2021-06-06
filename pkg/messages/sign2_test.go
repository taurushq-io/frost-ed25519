package messages

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
)

func TestSign2_MarshalBinary(t *testing.T) {
	from := party.RandID()
	s := scalar.NewScalarRandom()

	msg := NewSign2(from, s)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaler(msg, &msg2))
	require.True(t, msg.Equal(&msg2), "messages are not equal")
}
