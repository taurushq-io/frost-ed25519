package messages

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
)

func TestKeyGen2_MarshalBinary(t *testing.T) {
	from := party.ID(rand.Uint32())
	to := party.ID(rand.Uint32())
	secret := scalar.NewScalarRandom()

	msg := NewKeyGen2(from, to, secret)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaller(msg, &msg2))
	require.True(t, msg.Equal(&msg2), "messages are not equal")
}
