package messages

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/zk"
)

func TestKeyGen1_MarshalBinary(t *testing.T) {
	from := rand.Uint32()
	deg := uint32(10)
	secret := scalar.NewScalarRandom()
	context := make([]byte, 32)

	poly := polynomial.NewPolynomial(deg, secret)
	comm := polynomial.NewPolynomialExponent(poly)

	proof := zk.NewSchnorrProof(from, comm.Evaluate(0), context, poly.Evaluate(0))

	msg := NewKeyGen1(from, proof, comm)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaller(msg, &msg2))
	require.True(t, msg.Equal(&msg2), "messages are not equal")
}
