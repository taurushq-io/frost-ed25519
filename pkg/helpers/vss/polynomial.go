package vss

import (
	"errors"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

// samplePolynomial generates the coefficients of a polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q.
func samplePolynomial(t uint32, secret *edwards25519.Scalar) ([]*edwards25519.Scalar, error) {
	polynomial := make([]*edwards25519.Scalar, t+1) // polynomials are indexed starting at 0

	// Set the constant term to the secret
	polynomial[0] = new(edwards25519.Scalar).Set(secret)

	var err error
	for i := uint32(1); i <= t; i++ {
		polynomial[i], err = common.NewScalarRandom()
		if err != nil {
			return nil, fmt.Errorf("failed to sample polynomial: %w", err)
		}
	}

	return polynomial, nil
}

// computeCommitments returns the VSS commitments for a polynomial given by its coefficients
func computeCommitments(polynomial []*edwards25519.Scalar) []*edwards25519.Point {
	commitments := make([]*edwards25519.Point, len(polynomial))
	for i, c := range polynomial {
		commitments[i] = new(edwards25519.Point).ScalarBaseMult(c)
	}
	return commitments
}

func generateShares(polynomial []*edwards25519.Scalar, indices []common.Party) (Shares, error) {
	shares := make(Shares, len(indices))
	var err error
	for _, index := range indices {
		shares[index], err = evaluatePolynomial(polynomial, index.UInt32())
		if err != nil {
			return nil, fmt.Errorf("generateShares: index=%d: %w", index, err)
		}
	}
	return shares, nil
}


// evaluatePolynomial evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func evaluatePolynomial(polynomial []*edwards25519.Scalar, index uint32) (*edwards25519.Scalar, error) {
	result := edwards25519.NewScalar()
	x, err := common.NewScalarUInt32(index)
	if err != nil {
		return nil, fmt.Errorf("evaluate polynomial, index=%d: %w", index, err)
	}
	// revers order
	for i := len(polynomial) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(result, x, polynomial[i])
	}
	return result, nil
}

func evaluatePolynomialExponent(commitments []*edwards25519.Point, index common.Party) *edwards25519.Point {
	x0, err := common.NewScalarUInt32(index.UInt32())
	if err != nil {
		panic(err)
		return nil
	}
	x := new(edwards25519.Scalar).Set(x0)

	tmp := new(edwards25519.Point)
	result := new(edwards25519.Point).Set(commitments[0])

	for i := 1; i < len(commitments); i++ {
		tmp.ScalarMult(x, commitments[i])
		result.Add(result, tmp)
		x.Multiply(x, x0)
	}
	// This is an attempt at using horner, but it is more tricky.
	//n := len(commitments)
	//result := new(edwards25519.Point).Set(commitments[n-1])
	//identity := edwards25519.NewIdentityPoint()
	//x, err := common.NewScalarUInt32(index.UInt32())
	//if err != nil {
	//	return err
	//}
	//for i := len(commitments) - 2; i >= 0; i-- {
	//	result.
	//	// b_n-1•G = a_n-1•G + X.b_n•G
	//	result.ScalarMult(x, result)
	//	result.Add(result, commitments[i])
	//}

	return result
}

// verifyCommitments evaluates the polynomial f(index)•G and verifies that it equals share•G
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func verifyCommitments(commitments []*edwards25519.Point, share *edwards25519.Scalar, index common.Party) error {
	public := new(edwards25519.Point).ScalarBaseMult(share)

	result := evaluatePolynomialExponent(commitments, index)

	if public.Equal(result) != 1 {
		return errors.New("share is invalid")
	}
	return nil
}