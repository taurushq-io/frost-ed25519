package polynomial

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
)

func TestPolynomial_Evaluate(t *testing.T) {
	{
		polynomial := &Polynomial{make([]edwards25519.Scalar, 3)}
		polynomial.coefficients[0].Set(scalar.NewScalarUInt32(1))
		polynomial.coefficients[2].Set(scalar.NewScalarUInt32(1))

		for index := uint32(0); index < 100; index++ {
			x := party.RandID()
			max := 1 << 8 * int64(party.ByteSize)
			if int64(x) > max {
				continue
			}
			result := 1 + x*x
			computedResult := polynomial.Evaluate(party.ID(index).Scalar())
			expectedResult := result.Scalar()
			require.Equal(t, 1, expectedResult.Equal(computedResult))
		}
	}
}
