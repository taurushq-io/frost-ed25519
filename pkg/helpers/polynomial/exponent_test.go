package polynomial

import (
	"fmt"
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/common"
)

func TestExponent_Evaluate(t *testing.T) {
	for x := 0; x < 20; x++ {
		N := uint32(1000)
		secret := common.NewScalarRandom()
		poly := NewPolynomial(N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := uint32(rand.Int31n(4096))

		lhs := edwards25519.NewIdentityPoint().ScalarBaseMult(poly.Evaluate(randomIndex))
		rhs1 := polyExp.Evaluate(randomIndex)
		rhs2 := polyExp.evaluateSlow(randomIndex)

		fmt.Println(lhs.Bytes())
		fmt.Println(rhs1.Bytes())
		fmt.Println(rhs2.Bytes())
		assert.Equal(t, 1, lhs.Equal(rhs1), fmt.Sprint(x))
		assert.Equal(t, 1, lhs.Equal(rhs2), fmt.Sprint(x))
	}
}

func TestSum(t *testing.T) {
	N := 20
	Deg := uint32(10)

	randomIndex := uint32(rand.Int31n(4096))

	// compute f1(x) + f2(x) + ...
	evaluationScalar := edwards25519.NewScalar()

	// compute F1(x) + F2(x) + ...
	evaluationPartial := edwards25519.NewIdentityPoint()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i, _ := range polys {
		sec := common.NewScalarRandom()
		polys[i] = NewPolynomial(Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(evaluationScalar, polys[i].Evaluate(randomIndex))
		evaluationPartial.Add(evaluationPartial, polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + ...)(x)
	summedExp := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := edwards25519.NewIdentityPoint().ScalarBaseMult(evaluationScalar)
	assert.Equal(t, 1, evaluationSum.Equal(evaluationFromScalar))
	assert.Equal(t, 1, evaluationSum.Equal(evaluationPartial))
}
