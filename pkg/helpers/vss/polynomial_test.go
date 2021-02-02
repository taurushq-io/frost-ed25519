package vss

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"math/rand"
	"testing"
)

func Test_evaluatePolynomial_Constant(t *testing.T) {
	cst := common.NewScalarRandom()
	p := samplePolynomial(0, cst)

	eval1 := evaluatePolynomial(p, 0)
	require.Equal(t, 1, eval1.Equal(cst))

	eval2 := evaluatePolynomial(p, 10)
	require.Equal(t, 1, eval2.Equal(cst))

	eval3 := evaluatePolynomial(p, 3000)
	require.Equal(t, 1, eval3.Equal(cst))
}

func Test_evaluatePolynomial_x2plus1(t *testing.T) {
	polynomial := make([]*edwards25519.Scalar, 3)
	polynomial[0] = common.NewScalarUInt32(1)
	polynomial[1] = edwards25519.NewScalar()
	polynomial[2] = common.NewScalarUInt32(1)

	// TODO more finite field tests (more than uint 32)

	for index := uint32(0); index < 100; index++ {
		x := rand.Uint32()
		if x > 1<<16 {
			continue
		}
		result := 1 + x*x
		computedRestult := evaluatePolynomial(polynomial, result)
		expectedResult := common.NewScalarUInt32(result)
		require.Equal(t, 1, expectedResult.Equal(computedRestult))
	}
}
