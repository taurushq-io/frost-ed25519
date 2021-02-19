package polynomial

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

// ComputeLagrange gives the Lagrange coefficient l_j(x)
// for x = 0, since we are only interested in interpolating
// the constant coefficient.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//			( x  - x_0) ... ( x  - x_k)
// l_j(x) =	---------------------------
//			(x_j - x_0) ... (x_j - x_k)
//
//			        x_0 ... x_k
// l_j(0) =	---------------------------
//			(x_0 - x_j) ... (x_k - x_j)
func LagrangeCoefficient(selfIndex uint32, allIndices []uint32) *edwards25519.Scalar {
	var xM edwards25519.Scalar

	denum := scalar.NewScalarUInt32(uint32(1))
	num := scalar.NewScalarUInt32(uint32(1))

	xJ := scalar.NewScalarUInt32(selfIndex)

	for _, id := range allIndices {
		if id == selfIndex {
			continue
		}

		scalar.SetScalarUInt32(&xM, id)

		// num = x_0 * ... * x_k
		num.Multiply(num, &xM) // num * xM

		// denum = (x_0 - x_j) ... (x_k - x_j)
		xM.Subtract(&xM, xJ)       // = xM - xJ
		denum.Multiply(denum, &xM) // denum * (xm - xj)
	}

	// This should not happen since xM!=xJ
	if denum.Equal(edwards25519.NewScalar()) == 1 {
		panic(errors.New("others contained selfIndex"))
	}
	denum.Invert(denum)
	num.Multiply(num, denum)
	return num
}
