package polynomial

import (
	"fmt"
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestExponent_Evaluate(t *testing.T) {
	for x := 0; x < 5; x++ {
		N := uint32(1000)
		secret := scalar.NewScalarRandom()
		poly := NewPolynomial(N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := uint32(rand.Int31n(4096))

		lhs := edwards25519.NewIdentityPoint().ScalarBaseMult(poly.Evaluate(randomIndex))
		rhs1 := polyExp.evaluateHorner(randomIndex)
		rhs2 := polyExp.evaluateClassic(randomIndex)
		rhs3 := polyExp.evaluateVar(randomIndex)

		assert.Equal(t, 1, lhs.Equal(rhs1), fmt.Sprint(x))
		assert.Equal(t, 1, lhs.Equal(rhs2), fmt.Sprint(x))
		assert.Equal(t, 1, lhs.Equal(rhs3), fmt.Sprint(x))
	}
}

func Benchmark_Evaluate(b *testing.B) {
	N := uint32(100)
	secret := scalar.NewScalarRandom()
	poly := NewPolynomial(N, secret)
	polyExp := NewPolynomialExponent(poly)

	b.Run("normal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			randomIndex := uint32(rand.Uint64())
			polyExp.evaluateClassic(randomIndex)
		}
	})
	b.Run("horner", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			randomIndex := uint32(rand.Uint64())
			polyExp.evaluateHorner(randomIndex)
		}
	})
	b.Run("vartime", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			randomIndex := uint32(rand.Uint64())
			polyExp.evaluateVar(randomIndex)
		}
	})

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
		sec := scalar.NewScalarRandom()
		polys[i] = NewPolynomial(Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(evaluationScalar, polys[i].Evaluate(randomIndex))
		evaluationPartial.Add(evaluationPartial, polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + ...)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := edwards25519.NewIdentityPoint().ScalarBaseMult(evaluationScalar)
	assert.Equal(t, 1, evaluationSum.Equal(evaluationFromScalar))
	assert.Equal(t, 1, evaluationSum.Equal(evaluationPartial))
}
