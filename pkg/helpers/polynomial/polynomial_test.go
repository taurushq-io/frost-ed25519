package polynomial

import (
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

func TestPolynomial_Evaluate(t *testing.T) {
	{
		polynomial := &Polynomial{make([]edwards25519.Scalar, 3)}
		polynomial.coefficients[0].Set(common.NewScalarUInt32(1))
		polynomial.coefficients[2].Set(common.NewScalarUInt32(1))

		for index := uint32(0); index < 100; index++ {
			x := rand.Uint32()
			if x > 1<<16 {
				continue
			}
			result := 1 + x*x
			computedResult := polynomial.Evaluate(index)
			expectedResult := common.NewScalarUInt32(result)
			require.Equal(t, 1, expectedResult.Equal(computedResult))
		}
	}

}
