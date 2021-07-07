package messages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/zk"
)

func TestKeyGen1_MarshalBinary(t *testing.T) {
	from := party.RandID()
	deg := 25
	secret := scalar.NewScalarRandom()
	context := make([]byte, 32)

	poly := polynomial.NewPolynomial(party.Size(deg), secret)
	comm := polynomial.NewPolynomialExponent(poly)

	proof := zk.NewSchnorrProof(from, comm.Constant(), context, poly.Constant())

	msg := NewKeyGen1(from, proof, comm)

	var msg2 Message
	require.NoError(t, CheckFROSTMarshaler(msg, &msg2))
	assert.True(t, msg2.Equal(msg), "messages are not equal")
}
