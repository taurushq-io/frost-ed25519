package polynomial

import (
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/common"
)

type Exponent struct {
	coefficients []edwards25519.Point
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	polynomialExp := &Exponent{make([]edwards25519.Point, len(polynomial.coefficients))}
	for i, _ := range polynomialExp.coefficients {
		polynomialExp.coefficients[i].ScalarBaseMult(&polynomial.coefficients[i])
	}
	return polynomialExp
}

// evaluateSlow evaluates a polynomial in a given variable index
// We do the classic method.
func (p *Exponent) evaluateSlow(index uint32) *edwards25519.Point {
	var result, tmp edwards25519.Point
	var x, x0 edwards25519.Scalar

	common.SetScalarUInt32(&x, index)
	common.SetScalarUInt32(&x0, 1)

	zero := edwards25519.NewScalar()

	result.Set(edwards25519.NewIdentityPoint())
	for i := range p.coefficients {
		tmp.VarTimeDoubleScalarBaseMult(&x0, &p.coefficients[i], zero)
		//tmp.ScalarMult(&x0, &p.coefficients[i])
		result.Add(&result, &tmp)

		x0.Multiply(&x0, &x)
	}
	return &result
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Exponent) Evaluate(index uint32) *edwards25519.Point {
	if index == 0 {
		return &p.coefficients[0]
		//return result.Set(&p.coefficients[0])
	}

	var result edwards25519.Point
	var x edwards25519.Scalar

	result.Set(edwards25519.NewIdentityPoint())

	zero := edwards25519.NewScalar()
	common.SetScalarUInt32(&x, index)
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		//B_n-1 = [x]B_n  + A_n-1

		result.VarTimeDoubleScalarBaseMult(&x, &result, zero)
		//result.ScalarMult(&x, &result)
		result.Add(&result, &p.coefficients[i])
	}
	return &result
}

// EvaluateMulti evaluates a polynomial in a many given points.
func (p *Exponent) EvaluateMulti(indices []uint32) map[uint32]*edwards25519.Point {
	evaluations := make(map[uint32]*edwards25519.Point, len(indices))

	for _, id := range indices {
		evaluations[id] = p.Evaluate(id)
	}
	return evaluations
}

func (p *Exponent) Degree() uint32 {
	return uint32(len(p.coefficients)) - 1
}

func (p *Exponent) Add(q *Exponent) error {
	if len(p.coefficients) != len(q.coefficients) {
		return errors.New("q is not the same length as p")
	}

	for i := range p.coefficients {
		p.coefficients[i].Add(&p.coefficients[i], &q.coefficients[i])
	}

	return nil
}

// Sum creates a new Polynomial in the Exponent, by summing a slice of existing ones.
func Sum(polynomials []*Exponent) (*Exponent, error) {
	var summed Exponent
	var err error

	// Create the new polynomial by copying the first one given
	summed = *polynomials[0]

	// we assume all polynomials have the same degree as the first
	for j := range polynomials {
		if j == 0 {
			continue
		}
		err = summed.Add(polynomials[j])
		if err != nil {
			return nil, err
		}
	}
	return &summed, nil
}

//
// FROSTMarshaller
//

func (p *Exponent) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, p.Size())
	return p.BytesAppend(buf)
}

func (p *Exponent) UnmarshalBinary(data []byte) error {
	coefficientCount := binary.BigEndian.Uint32(data[:4])
	p.coefficients = make([]edwards25519.Point, coefficientCount)

	remaining := data[4:]
	count := len(remaining)
	if count%32 != 0 {
		return errors.New("length of data is wrong")
	}
	if count/32 != len(p.coefficients) {
		return errors.New("wrong number of coefficients embedded")
	}
	var err error
	for i := 0; i < len(p.coefficients); i++ {
		NextScalarBytes := remaining[i*32 : (i+1)*32]
		_, err = p.coefficients[i].SetBytes(NextScalarBytes)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Exponent) BytesAppend(existing []byte) (data []byte, err error) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(p.coefficients)))
	existing = append(existing, size[:]...)
	for i := range p.coefficients {
		existing = append(existing, p.coefficients[i].Bytes()...)
	}
	return existing, nil
}

func (p *Exponent) Size() int {
	return 4 + 32*len(p.coefficients)
}

func (p *Exponent) Copy() *Exponent {
	q := Exponent{coefficients: make([]edwards25519.Point, len(p.coefficients))}
	for i := range p.coefficients {
		q.coefficients[i].Set(&p.coefficients[i])
	}
	return &q
}
