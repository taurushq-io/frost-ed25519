package messages

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"
	"github.com/taurusgroup/tg-tss/pkg/helpers/zk"
	"math/rand"
	"testing"
)

func TestKeyGen1_MarshalBinary(t *testing.T) {
	from := rand.Uint32()
	params := ""
	deg := uint32(10)
	secret := common.NewScalarRandom()
	proof, public := zk.NewSchnorrProof(secret, from, params)

	poly := polynomial.NewPolynomial(deg, secret)
	comm := polynomial.NewPolynomialExponent(poly)

	msg := NewKeyGen1(from, proof, comm)

	msgBytes, err := msg.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	msgDec := new(Message)
	err = msgDec.UnmarshalBinary(msgBytes)
	require.NoError(t, err, "unmarshalling failed")

	msgDecBytes, err := msgDec.MarshalBinary()
	require.NoError(t, err, "marshalling failed")

	assert.True(t, bytes.Equal(msgBytes, msgDecBytes), "unmarshal -> marshal should give the same result")

	require.NotNil(t, msgDec.KeyGen1, "keygen1 is nil")
	require.NotNil(t, msgDec.KeyGen1.Proof, "proof is nil")
	require.NotNil(t, msgDec.KeyGen1.Commitments, "commitments is nil")

	assert.True(t, msgDec.KeyGen1.Proof.Verify(public, from, params), "zk failed to verify")
	assert.Equal(t, deg, msgDec.KeyGen1.Commitments.Degree(), "wrong degree commitment")
	assert.Equal(t, msg.From, msgDec.From, "from is not the same")
	assert.Equal(t, MessageTypeKeyGen1, msgDec.Type, "type is wrong")
}
