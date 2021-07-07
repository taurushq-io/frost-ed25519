package polynomial

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestPolynomial_Evaluate(t *testing.T) {
	{
		polynomial := &Polynomial{make([]ristretto.Scalar, 3)}
		polynomial.coefficients[0] = *scalar.NewScalarUInt32(1)
		polynomial.coefficients[1] = *scalar.NewScalarUInt32(0)
		polynomial.coefficients[2] = *scalar.NewScalarUInt32(1)

		for index := uint32(0); index < 100; index++ {
			x := party.RandID()
			xUint := uint64(x)
			expectedResult := 1 + xUint*xUint
			computedResultScalar := polynomial.Evaluate(x.Scalar())
			computedResult := binary.LittleEndian.Uint64(computedResultScalar.Bytes())
			assert.Equal(t, int(expectedResult), int(computedResult))
		}
	}
}
