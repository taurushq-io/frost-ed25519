package messages

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestSign1_MarshalBinary(t *testing.T) {
	d := scalar.NewScalarRandom()
	e := scalar.NewScalarRandom()
	D := new(edwards25519.Point).ScalarBaseMult(d)
	E := new(edwards25519.Point).ScalarBaseMult(e)

	from := uint32(42)

	msg := NewSign1(from, D, E)

	var msgDec Message
	require.NoError(t, CheckFROSTMarshaller(msg, &msgDec))
	require.True(t, msg.Equal(&msgDec), "messages are not equal")
}
