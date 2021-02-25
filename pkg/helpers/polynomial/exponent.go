package polynomial

import (
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

type Exponent struct {
	coefficients []*edwards25519.Point
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	var coefficients = make([]edwards25519.Point, len(polynomial.coefficients))
	var p Exponent

	p.coefficients = make([]*edwards25519.Point, len(polynomial.coefficients))
	for i := range coefficients {
		p.coefficients[i] = coefficients[i].ScalarBaseMult(&polynomial.coefficients[i])
	}

	return &p
}

// Evaluate uses any one of the defined evaluation algorithms
func (p *Exponent) Evaluate(index uint32) *edwards25519.Point {
	if index == 0 {
		return p.coefficients[0]
	}

	//return p.evaluateClassic(index)
	//return p.evaluateHorner(index)
	return p.evaluateVar(index)
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method.
func (p *Exponent) evaluateClassic(index uint32) *edwards25519.Point {
	var result, tmp edwards25519.Point

	x := scalar.NewScalarUInt32(index)
	x0 := scalar.NewScalarUInt32(1)

	zero := edwards25519.NewScalar()

	result.Set(edwards25519.NewIdentityPoint())
	for i := range p.coefficients {
		tmp.VarTimeDoubleScalarBaseMult(x0, p.coefficients[i], zero)
		result.Add(&result, &tmp)

		x0.Multiply(x0, x)
	}
	return &result
}

// evaluateVar evaluates a polynomial in a given variable index.
// We exploit the fact that edwards25519.Point.VarTimeMultiScalarMult is a lot faster
// than other Point ops, but this requires us to have access to an array of powers of index.
//
//
func (p *Exponent) evaluateVar(index uint32) *edwards25519.Point {
	var result edwards25519.Point

	x := scalar.NewScalarUInt32(index)

	powers := make([]edwards25519.Scalar, len(p.coefficients))
	powersPointers := make([]*edwards25519.Scalar, len(p.coefficients))

	for i := range p.coefficients {
		switch {
		case i == 0:
			powersPointers[i] = scalar.SetScalarUInt32(&powers[0], 1)
		case i == 1:
			powersPointers[i] = powers[1].Set(x)
		default:
			powersPointers[i] = powers[i].Multiply(&powers[i-1], x)
		}
	}
	return result.VarTimeMultiScalarMult(powersPointers, p.coefficients)
}

// evaluateHorner evaluates a polynomial in a given variable index
// We create a list of all powers of index, and use VarTimeMultiScalarMult
// to speed things up
func (p *Exponent) evaluateHorner(index uint32) *edwards25519.Point {
	var result edwards25519.Point
	x := scalar.NewScalarUInt32(index)

	zero := edwards25519.NewScalar()

	result.Set(edwards25519.NewIdentityPoint())

	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// B_n-1 = [x]B_n  + A_n-1
		result.VarTimeDoubleScalarBaseMult(x, &result, zero)
		result.Add(&result, p.coefficients[i])
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
		p.coefficients[i].Add(p.coefficients[i], q.coefficients[i])
	}

	return nil
}

// Sum creates a new Polynomial in the Exponent, by summing a slice of existing ones.
func Sum(polynomials []*Exponent) (*Exponent, error) {
	var err error

	// Create the new polynomial by copying the first one given
	summed := polynomials[0].Copy()

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
	return summed, nil
}

// Reset sets all coefficients to 0
func (p *Exponent) Reset() {
	one := edwards25519.NewIdentityPoint()
	for i := range p.coefficients {
		p.coefficients[i].Set(one)
	}
	p.coefficients = []*edwards25519.Point{}
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

	coefficients := make([]edwards25519.Point, coefficientCount)
	p.coefficients = make([]*edwards25519.Point, coefficientCount)

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
		p.coefficients[i], err = coefficients[i].SetBytes(NextScalarBytes)
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
	var q Exponent
	coefficients := make([]edwards25519.Point, len(p.coefficients))
	q.coefficients = make([]*edwards25519.Point, len(p.coefficients))
	for i := range p.coefficients {
		q.coefficients[i] = coefficients[i].Set(p.coefficients[i])
	}
	return &q
}

func (p *Exponent) Equal(other interface{}) bool {
	otherExponent, ok := other.(*Exponent)
	if !ok {
		return false
	}
	if len(p.coefficients) != len(otherExponent.coefficients) {
		return false
	}
	for i := range p.coefficients {
		if p.coefficients[i].Equal(otherExponent.coefficients[i]) != 1 {
			return false
		}
	}
	return true
}
