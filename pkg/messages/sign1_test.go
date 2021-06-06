package messages

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestSign1_MarshalBinary(t *testing.T) {
	d := scalar.NewScalarRandom()
	e := scalar.NewScalarRandom()
	D := new(ristretto.Element).ScalarBaseMult(d)
	E := new(ristretto.Element).ScalarBaseMult(e)

	from := party.ID(42)

	msg := NewSign1(from, D, E)

	var msgDec Message
	require.NoError(t, CheckFROSTMarshaler(msg, &msgDec))
	require.True(t, msg.Equal(&msgDec), "messages are not equal")
}
