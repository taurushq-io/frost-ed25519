package polynomial

import (
	"crypto/rand"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

type Polynomial struct {
	coefficients []edwards25519.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomial(degree party.Size, constant *edwards25519.Scalar) *Polynomial {
	var polynomial Polynomial
	polynomial.coefficients = make([]edwards25519.Scalar, degree+1)

	// SetWithoutSelf the constant term to the secret
	polynomial.coefficients[0].Set(constant)

	var randomBytes [64]byte
	for i := party.Size(1); i <= degree; i++ {
		_, _ = rand.Read(randomBytes[:64])
		polynomial.coefficients[i].SetUniformBytes(randomBytes[:64])
	}

	return &polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index *edwards25519.Scalar) *edwards25519.Scalar {
	if index.Equal(edwards25519.NewScalar()) == 1 {
		panic("attempt to leak secret")
	}

	var result edwards25519.Scalar
	// reverse order
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(&result, index, &p.coefficients[i])
	}
	return &result
}

func (p *Polynomial) Constant() *edwards25519.Scalar {
	var result edwards25519.Scalar
	result.Set(&p.coefficients[0])
	return &result
}

// Degree is the highest power of the Polynomial
func (p *Polynomial) Degree() party.Size {
	return party.Size(len(p.coefficients)) - 1
}

// Size is the number of coefficients of the polynomial
// It is equal to Degree+1
func (p *Polynomial) Size() int {
	return len(p.coefficients)
}

// Reset sets all coefficients to 0
func (p *Polynomial) Reset() {
	zero := edwards25519.NewScalar()
	for i := range p.coefficients {
		p.coefficients[i].Set(zero)
	}
}
