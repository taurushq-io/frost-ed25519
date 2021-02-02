package vss

import (
	"errors"
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

// samplePolynomial generates the coefficients of a polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q.
func samplePolynomial(t uint32, secret *edwards25519.Scalar) []*edwards25519.Scalar {
	polynomial := make([]*edwards25519.Scalar, t+1) // polynomials are indexed starting at 0

	// Set the constant term to the secret
	polynomial[0] = new(edwards25519.Scalar).Set(secret)

	for i := uint32(1); i <= t; i++ {
		polynomial[i] = common.NewScalarRandom()
	}

	return polynomial
}

// computeCommitments returns the VSS commitments for a polynomial given by its coefficients
func computeCommitments(polynomial []*edwards25519.Scalar) []*edwards25519.Point {
	commitments := make([]*edwards25519.Point, len(polynomial))
	for i, c := range polynomial {
		commitments[i] = new(edwards25519.Point).ScalarBaseMult(c)
	}
	return commitments
}

func generateShares(polynomial []*edwards25519.Scalar, indices []uint32) Shares {
	shares := make(Shares, len(indices))
	for _, index := range indices {
		shares[index] = evaluatePolynomial(polynomial, index)
	}
	return shares
}

// evaluatePolynomial evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func evaluatePolynomial(polynomial []*edwards25519.Scalar, index uint32) *edwards25519.Scalar {
	result := edwards25519.NewScalar()
	x := common.NewScalarUInt32(index)
	// revers order
	for i := len(polynomial) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(result, x, polynomial[i])
	}
	return result
}

// evaluatePolynomial evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func evaluatePolynomialExponent(commitments []*edwards25519.Point, index uint32) *edwards25519.Point {
	x := common.NewScalarUInt32(index)
	result := edwards25519.NewIdentityPoint()

	tmp := new(edwards25519.Point)

	for i := len(commitments) - 1; i >= 0; i-- {
		// B_n-1 = [x]B_n  + A_n-1
		tmp.ScalarMult(x, result)
		tmp.Add(tmp, commitments[i])
		result.Add(result, tmp)
	}
	return result
}

// verifyCommitments evaluates the polynomial f(index)•G and verifies that it equals share•G
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func verifyCommitments(commitments []*edwards25519.Point, share *edwards25519.Scalar, index uint32) error {
	public := new(edwards25519.Point).ScalarBaseMult(share)

	result := evaluatePolynomialExponent(commitments, index)

	if public.Equal(result) != 1 {
		return errors.New("share is invalid")
	}
	return nil
}
