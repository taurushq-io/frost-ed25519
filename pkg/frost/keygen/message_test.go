package keygen

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"
	"github.com/taurusgroup/tg-tss/pkg/helpers/zk"
	"math/rand"
	"testing"
)

func TestMsg1_MarshalBinary(t *testing.T) {
	from := rand.Uint32()
	deg := uint32(10)
	secret := common.NewScalarRandom()
	proof, _ := zk.NewSchnorrProof(secret, from, "")

	poly := polynomial.NewPolynomial(deg, secret)
	comm := polynomial.NewPolynomialExponent(poly)

	m := Msg1{
		From:        from,
		Proof:       proof,
		Commitments: comm,
	}
	mBytes, err := m.MarshalBinary()
	assert.NoError(t, err, "failed to marshal")

	m2 := new(Msg1)
	err = m2.UnmarshalBinary(mBytes)
	assert.NoError(t, err, "failed to unmarshal")

	m2Bytes, err := m2.MarshalBinary()
	assert.NoError(t, err, "failed to marshal")

	assert.True(t, bytes.Equal(mBytes, m2Bytes))
	assert.Equal(t, from, m2.From)
}

func TestMsg2_MarshalBinary(t *testing.T) {
	from := rand.Uint32()
	to := rand.Uint32()
	secret := common.NewScalarRandom()

	m := Msg2{
		From:        from,
		To: to,
		Share:       secret,
	}
	mBytes, err := m.MarshalBinary()
	assert.NoError(t, err, "failed to marshal")

	m2 := new(Msg2)
	err = m2.UnmarshalBinary(mBytes)
	assert.NoError(t, err, "failed to unmarshal")

	m2Bytes, err := m2.MarshalBinary()
	assert.NoError(t, err, "failed to marshal")

	assert.True(t, bytes.Equal(mBytes, m2Bytes))

	assert.Equal(t, 1, m2.Share.Equal(m.Share))
	assert.Equal(t, from, m2.From)
	assert.Equal(t, to, m2.To)
}

