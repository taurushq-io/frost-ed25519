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
	params := ""
	deg := uint32(10)
	secret := scalar.NewScalarRandom()
	proof, _ := zk.NewSchnorrProof(secret, from, params)

	poly := polynomial.NewPolynomial(deg, secret)
	comm := polynomial.NewPolynomialExponent(poly)

	msg := NewKeyGen1(from, proof, comm)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaller(msg, &msg2))
	require.True(t, msg.Equal(&msg2), "messages are not equal")
}
