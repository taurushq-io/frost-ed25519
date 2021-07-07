package messages

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.Equal(t, *msg, msg2, "messages are not equal")
}
