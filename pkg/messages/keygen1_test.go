package messages

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/zk"
)

func TestKeyGen1_MarshalBinary(t *testing.T) {
	from := party.RandID()
	deg := party.RandIDn(100)
	secret := scalar.NewScalarRandom()
	context := make([]byte, 32)

	poly := polynomial.NewPolynomial(deg, secret)
	comm := polynomial.NewPolynomialExponent(poly)

	proof := zk.NewSchnorrProof(from, comm.Constant(), context, poly.Constant())

	msg := NewKeyGen1(from, proof, comm)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaler(msg, &msg2))
	require.True(t, msg.Equal(&msg2), "messages are not equal")
}
