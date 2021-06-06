package polynomial

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type Polynomial struct {
	coefficients []ristretto.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomial(degree party.Size, constant *ristretto.Scalar) *Polynomial {
	var polynomial Polynomial
	polynomial.coefficients = make([]ristretto.Scalar, degree+1)

	// SetWithoutSelf the constant term to the secret
	polynomial.coefficients[0].Set(constant)

	var err error
	randomBytes := make([]byte, 64)
	for i := party.Size(1); i <= degree; i++ {
		_, err = rand.Read(randomBytes)
		if err != nil {
			panic(fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err))
		}
		polynomial.coefficients[i].SetUniformBytes(randomBytes)
	}

	return &polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index *ristretto.Scalar) *ristretto.Scalar {
	if index.Equal(ristretto.NewScalar()) == 1 {
		panic("attempt to leak secret")
	}

	var result ristretto.Scalar
	// reverse order
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(&result, index, &p.coefficients[i])
	}
	return &result
}

func (p *Polynomial) Constant() *ristretto.Scalar {
	var result ristretto.Scalar
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
	zero := ristretto.NewScalar()
	for i := range p.coefficients {
		p.coefficients[i].Set(zero)
	}
}
