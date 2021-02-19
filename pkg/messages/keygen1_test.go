package messages

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
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
	proof, public := zk.NewSchnorrProof(secret, from, params)

	poly := polynomial.NewPolynomial(deg, secret)
	comm := polynomial.NewPolynomialExponent(poly)

	msg := NewKeyGen1(from, proof, comm)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaller(msg, &msg2))

	require.NotNil(t, msg2, "keygen1 is nil")
	require.NotNil(t, msg2.KeyGen1.Proof, "proof is nil")
	require.NotNil(t, msg2.KeyGen1.Commitments, "commitments is nil")

	assert.True(t, msg2.KeyGen1.Proof.Verify(public, from, params), "zk failed to verify")
	assert.Equal(t, deg, msg2.KeyGen1.Commitments.Degree(), "wrong degree commitment")
	assert.Equal(t, msg.From, msg2.From, "from is not the same")
	assert.Equal(t, MessageTypeKeyGen1, msg2.Type, "type is wrong")
}
