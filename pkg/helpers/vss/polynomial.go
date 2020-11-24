package vss

import (
	"crypto/rand"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers"
	"math/big"
)

type Polynomial []*big.Int
type PolynomialExp []*common.ECPoint

// newRandomPolynomial generates the coefficients of a Polynomial f(X) = a0 + a1*X + ... + at*X^t,
// with coefficients in Z_q. The constant coefficient a0 can be nil, in which case it is samples uniformly.
// All other coefficients are sampled uniformly from Z_q as well.
func newRandomPolynomial(t int, a0 *big.Int) (Polynomial, error) {
	polynomial := make(Polynomial, t+1)
	i := 0
	if a0 != nil {
		polynomial[0] = a0.Mod(a0, common.Modulus())
		i = 1
	}
	var err error
	for ; i <= t; i++ {
		polynomial[i], err = rand.Int(rand.Reader, common.Modulus())
		if err != nil {
			return nil, fmt.Errorf("failed to sample polynomial")
		}
	}

	return polynomial, nil
}

// convertPolynomial takes a Polynomial over Z_q and applies the transformation ai -> Ai = ai • G to all the coefficients.
// The result is a PolynomialExp which can be seen as f(X)•G.
func convertPolynomial(p Polynomial) PolynomialExp {
	pExp := make(PolynomialExp, len(p))
	for i, c := range p {
		pExp[i] = common.NewECPointBaseMult(c.Bytes())
	}
	return pExp
}

// evaluatePolynomial evaluates a Polynomial in a given variable x
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func evaluatePolynomial(p Polynomial, x *big.Int) *big.Int {
	result := new(big.Int)
	for i := len(p) - 1; i >= 0; i-- {
		// b_n-1 = a_n-1 + b_n * x
		result = result.Mul(result, x)
		result = result.Add(result, p[i])
		result = result.Mod(result, common.Modulus())
	}
	return result
}

// evaluatePolynomialExp evaluates a PolynomialExp in a given variable x
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func evaluatePolynomialExp(p PolynomialExp, x *big.Int) *common.ECPoint {
	result := common.NewECPointBaseMult(new(big.Int).Bytes())
	xBytes := x.Bytes()
	for i := len(p) - 1; i >= 0; i-- {
		// b_n-1•G = a_n-1•G + X.b_n•G
		result = result.ScalarMult(xBytes).Add(p[i])
	}
	return result
}
