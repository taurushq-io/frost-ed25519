package polynomial

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestExponent_Evaluate(t *testing.T) {
	var lhs ristretto.Element
	var rhs1, rhs2, rhs3 ristretto.Element
	for x := 0; x < 5; x++ {
		N := party.Size(1000)
		secret := scalar.NewScalarRandom()
		poly := NewPolynomial(N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := party.RandID().Scalar()

		lhs.ScalarBaseMult(poly.Evaluate(randomIndex))
		polyExp.evaluateHorner(randomIndex, &rhs1)
		polyExp.evaluateClassic(randomIndex, &rhs2)
		polyExp.evaluateVar(randomIndex, &rhs3)

		assert.Equal(t, 1, lhs.Equal(&rhs1), fmt.Sprint(x))
		assert.Equal(t, 1, lhs.Equal(&rhs2), fmt.Sprint(x))
		assert.Equal(t, 1, lhs.Equal(&rhs3), fmt.Sprint(x))
	}
}

func Benchmark_Evaluate(b *testing.B) {
	N := party.Size(100)
	secret := scalar.NewScalarRandom()
	poly := NewPolynomial(N, secret)
	polyExp := NewPolynomialExponent(poly)

	b.Run("normal", func(b *testing.B) {
		var result ristretto.Element
		for i := 0; i < b.N; i++ {
			randomIndex := party.RandID().Scalar()
			polyExp.evaluateClassic(randomIndex, &result)
		}
	})
	b.Run("horner", func(b *testing.B) {
		var result ristretto.Element
		for i := 0; i < b.N; i++ {
			randomIndex := party.RandID().Scalar()
			polyExp.evaluateHorner(randomIndex, &result)
		}
	})
	b.Run("vartime", func(b *testing.B) {
		var result ristretto.Element
		for i := 0; i < b.N; i++ {
			randomIndex := party.RandID().Scalar()
			polyExp.evaluateVar(randomIndex, &result)
		}
	})
}

func TestSum(t *testing.T) {
	N := 20
	Deg := party.Size(10)

	randomIndex := party.RandID().Scalar()

	// compute f1(x) + f2(x) + ...
	evaluationScalar := ristretto.NewScalar()

	// compute F1(x) + F2(x) + ...
	evaluationPartial := ristretto.NewIdentityElement()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i := range polys {
		sec := scalar.NewScalarRandom()
		polys[i] = NewPolynomial(Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(evaluationScalar, polys[i].Evaluate(randomIndex))
		evaluationPartial.Add(evaluationPartial, polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + ...)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := ristretto.NewIdentityElement().ScalarBaseMult(evaluationScalar)
	assert.Equal(t, 1, evaluationSum.Equal(evaluationFromScalar))
	assert.Equal(t, 1, evaluationSum.Equal(evaluationPartial))
}
