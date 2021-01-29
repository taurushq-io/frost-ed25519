package vss

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"math/rand"
	"testing"
)

func Test_evaluatePolynomial_Constant(t *testing.T) {
	cst, err := common.NewScalarRandom()
	require.NoError(t, err)
	p, err := samplePolynomial(0, cst)

	eval1, err := evaluatePolynomial(p, 0)
	require.NoError(t, err)
	require.Equal(t, 1, eval1.Equal(cst))

	eval2, err := evaluatePolynomial(p, 10)
	require.NoError(t, err)
	require.Equal(t, 1, eval2.Equal(cst))

	eval3, err := evaluatePolynomial(p, 3000)
	require.NoError(t, err)
	require.Equal(t, 1, eval3.Equal(cst))
}

func Test_evaluatePolynomial_x2plus1(t *testing.T) {
	polynomial := make([]*edwards25519.Scalar, 3)
	var err error
	polynomial[0], err = common.NewScalarUInt32(1)
	require.NoError(t, err)
	polynomial[1] = edwards25519.NewScalar()
	polynomial[2], err = common.NewScalarUInt32(1)
	require.NoError(t, err)

	// TODO more finite field tests (more than uint 32)

	for index := uint32(0); index < 100; index++ {
		x := rand.Uint32()
		if x > 1<<16 {
			continue
		}
		result := 1 + x*x
		computedRestult, err := evaluatePolynomial(polynomial, result)
		require.NoError(t, err)
		expectedResult, err := common.NewScalarUInt32(result)
		require.NoError(t, err)
		require.Equal(t, 1, expectedResult.Equal(computedRestult))
	}
}
