package vss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"
	"math/big"
)

type (
	Polynomial    []*big.Int
	PolynomialExp []curve.ECPoint
)

// NewRandomPolynomial generates the coefficients of a Polynomial f(X) = a0 + a1*X + ... + at*X^t,
// with coefficients in Z_q. The constant coefficient a0 can be nil, in which case it is samples uniformly.
// All other coefficients are sampled uniformly from Z_q as well.
func NewRandomPolynomial(degree uint32, a0 *big.Int) (Polynomial, error) {
	polynomial := make(Polynomial, degree+1)
	i := uint32(0)
	if a0 != nil {
		polynomial[0].Mod(a0, curve.Modulus())
		i = 1
	}
	var err error
	for ; i <= degree; i++ {
		polynomial[i], err = rand.Int(rand.Reader, curve.Modulus())
		if err != nil {
			return nil, fmt.Errorf("failed to sample polynomial")
		}
	}

	return polynomial, nil
}

// ConvertPolynomial takes a Polynomial over Z_q and applies the transformation ai -> Ai = ai • G to all the coefficients.
// The result is a PolynomialExp which can be seen as f(X)•G.
func ConvertPolynomial(p Polynomial) PolynomialExp {
	pExp := make(PolynomialExp, len(p))
	for i, c := range p {
		pExp[i] = curve.NewECPointBaseMult(c.Bytes())
	}
	return pExp
}

// Evaluate evaluates a Polynomial in a given variable x
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p Polynomial) Evaluate(x *big.Int) *big.Int {
	result := new(big.Int)
	for i := len(p) - 1; i >= 0; i-- {
		// b_n-1 = a_n-1 + b_n * x
		result.Mul(result, x)
		result.Add(result, p[i])
		result.Mod(result, curve.Modulus())
	}
	return result
}

// Evaluate evaluates a PolynomialExp in a given variable x
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (pe PolynomialExp) Evaluate(x *big.Int) curve.ECPoint {
	result := curve.NewECPointInfinity()
	xBytes := x.Bytes()
	for i := len(pe) - 1; i >= 0; i-- {
		// b_n-1•G = a_n-1•G + X.b_n•G
		result = result.ScalarMult(xBytes).Add(pe[i])
	}
	return result
}

// PolynomialExp.Bytes creates a byte slice which is the concatenation of all coefficients
func (pe PolynomialExp) Bytes() []byte {
	var flat []byte
	for _, point := range pe {
		flat = append(flat, point.Bytes()...)
	}
	return flat
}

// SumPolynomialExp returns a PolynomialExp which is the sum of all PolynomialExp given as argument.
// The degree of the coefficients must all be the same.
func SumPolynomialExp(polynomials []PolynomialExp) (PolynomialExp, error) {
	if len(polynomials) == 0 {
		return PolynomialExp{}, errors.New("no polynomials given")
	}
	degree := len(polynomials[0])
	newPolynomial := make([]curve.ECPoint, degree)
	var err error
	for i, coefficient := range polynomials[0] {
		newPolynomial[i], err = curve.NewECPoint(coefficient.X(), coefficient.Y())
		if err != nil {
			return PolynomialExp{}, fmt.Errorf("failed to create point: %w", err)
		}
	}
	for _, p := range polynomials[1:] {
		if len(p) != degree {
			return PolynomialExp{}, errors.New("degree mismatch")
		}
		for i, coefficient := range p {
			newPolynomial[i].Add(coefficient)
		}
	}
	return newPolynomial, nil
}
