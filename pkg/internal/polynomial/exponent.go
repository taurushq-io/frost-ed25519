package polynomial

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
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
func (p *Exponent) Evaluate(index *edwards25519.Scalar) *edwards25519.Point {
	var result edwards25519.Point
	// We chose evaluateVar since it is the fastest in CPU time, even though it uses more memory
	return p.evaluateVar(index, &result)
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method.
func (p *Exponent) evaluateClassic(index *edwards25519.Scalar, result *edwards25519.Point) *edwards25519.Point {
	if index.Equal(edwards25519.NewScalar()) == 1 {
		panic("you should be using .Constant() instead")
	}

	var tmp edwards25519.Point

	x := scalar.NewScalarUInt32(1)

	zero := edwards25519.NewScalar()

	result.Set(edwards25519.NewIdentityPoint())
	for i := 0; i < len(p.coefficients); i++ {
		tmp.VarTimeDoubleScalarBaseMult(x, p.coefficients[i], zero)
		result.Add(result, &tmp)

		x.Multiply(x, index)
	}
	return result
}

// evaluateVar evaluates a polynomial in a given variable index.
// We exploit the fact that edwards25519.Point.VarTimeMultiScalarMult is a lot faster
// than other Point ops, but this requires us to have access to an array of powers of index.
func (p *Exponent) evaluateVar(index *edwards25519.Scalar, result *edwards25519.Point) *edwards25519.Point {
	if index.Equal(edwards25519.NewScalar()) == 1 {
		panic("you should be using .Constant() instead")
	}
	powers := make([]edwards25519.Scalar, len(p.coefficients))
	powersPointers := make([]*edwards25519.Scalar, len(p.coefficients))

	for i := 0; i < len(p.coefficients); i++ {
		switch {
		case i == 0:
			powersPointers[i] = scalar.SetScalarUInt32(&powers[0], 1)
		case i == 1:
			powersPointers[i] = powers[1].Set(index)
		default:
			powersPointers[i] = powers[i].Multiply(&powers[i-1], index)
		}
	}
	result.VarTimeMultiScalarMult(powersPointers, p.coefficients)
	return result
}

// evaluateHorner evaluates a polynomial in a given variable index
// We create a list of all powers of index, and use VarTimeMultiScalarMult
// to speed things up
func (p *Exponent) evaluateHorner(index *edwards25519.Scalar, result *edwards25519.Point) *edwards25519.Point {
	if index.Equal(edwards25519.NewScalar()) == 1 {
		panic("you should be using .Constant() instead")
	}

	zero := edwards25519.NewScalar()

	result.Set(edwards25519.NewIdentityPoint())

	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// B_n-1 = [x]B_n  + A_n-1
		result.VarTimeDoubleScalarBaseMult(index, result, zero)
		result.Add(result, p.coefficients[i])
	}
	return result
}

// EvaluateMulti evaluates a polynomial in a many given points.
func (p *Exponent) EvaluateMulti(indices []party.ID) map[party.ID]*edwards25519.Point {
	evaluations := make(map[party.ID]*edwards25519.Point, len(indices))

	for _, id := range indices {
		evaluations[id] = p.Evaluate(id.Scalar())
	}
	return evaluations
}

func (p *Exponent) Degree() party.Size {
	return party.Size(len(p.coefficients)) - 1
}

func (p *Exponent) Add(q *Exponent) error {
	if len(p.coefficients) != len(q.coefficients) {
		return errors.New("q is not the same length as p")
	}

	for i := 0; i < len(p.coefficients); i++ {
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
	for i := 0; i < len(p.coefficients); i++ {
		p.coefficients[i].Set(edwards25519.NewIdentityPoint())
	}
}

//
// FROSTMarshaller
//

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (p *Exponent) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, p.Size())
	return p.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (p *Exponent) UnmarshalBinary(data []byte) error {
	coefficientCount := party.FromBytes(data) + 1
	remaining := data[party.ByteSize:]

	coefficients := make([]edwards25519.Point, coefficientCount)
	p.coefficients = make([]*edwards25519.Point, coefficientCount)

	count := len(remaining)
	if count%32 != 0 {
		return errors.New("length of data is wrong")
	}
	if count/32 != len(p.coefficients) {
		return errors.New("wrong number of coefficients embedded")
	}
	var err error
	for i := 0; i < len(p.coefficients); i++ {
		p.coefficients[i], err = coefficients[i].SetBytes(remaining[:32])
		remaining = remaining[32:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Exponent) BytesAppend(existing []byte) (data []byte, err error) {
	existing = append(existing, p.Degree().Bytes()...)
	for i := 0; i < len(p.coefficients); i++ {
		existing = append(existing, p.coefficients[i].Bytes()...)
	}
	return existing, nil
}

func (p *Exponent) Size() int {
	return party.ByteSize + 32*len(p.coefficients)
}

func (p *Exponent) Copy() *Exponent {
	var q Exponent
	coefficients := make([]edwards25519.Point, len(p.coefficients))
	q.coefficients = make([]*edwards25519.Point, len(p.coefficients))
	for i := 0; i < len(p.coefficients); i++ {
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
	for i := 0; i < len(p.coefficients); i++ {
		if p.coefficients[i].Equal(otherExponent.coefficients[i]) != 1 {
			return false
		}
	}
	return true
}

func (p *Exponent) Constant() *edwards25519.Point {
	var result edwards25519.Point
	result.Set(p.coefficients[0])
	return &result
}

func (p *Exponent) AddConstant(c *edwards25519.Point) *Exponent {
	q := p.Copy()
	q.coefficients[0].Add(q.coefficients[0], c)
	return q
}
