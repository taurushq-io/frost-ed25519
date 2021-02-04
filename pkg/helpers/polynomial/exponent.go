package polynomial

import (
	"encoding/binary"
	"errors"
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
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

// evaluatePolynomial evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Exponent) Evaluate(index uint32) *edwards25519.Point {
	var result, tmp edwards25519.Point
	result.Set(edwards25519.NewIdentityPoint())
	x := common.NewScalarUInt32(index)
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		//B_n-1 = [x]B_n  + A_n-1
		tmp.Set(edwards25519.NewIdentityPoint()) // TODO wait for ed fix
		tmp.ScalarMult(x, &result)
		result.Set(&tmp)
		//result.Add(result, tmp)
		result.Add(&result, &p.coefficients[i])
	}
	return &result
}

func (p *Exponent) Degree() uint32 {
	return uint32(len(p.coefficients)) - 1
}

func Sum(polynomials []*Exponent) *Exponent {
	degree := polynomials[0].Degree()
	size := len(polynomials[0].coefficients)
	summed := &Exponent{make([]edwards25519.Point, size)}
	for i := range polynomials[0].coefficients {
		summed.coefficients[i].Set(&polynomials[0].coefficients[i])
	}
	for j, p := range polynomials {
		if j == 0 {
			continue
		}
		if p.Degree() != degree {
			panic("polynomials have different lengths")
		}
		for i := range p.coefficients {
			summed.coefficients[i].Add(&summed.coefficients[i], &polynomials[j].coefficients[i])
		}
	}
	return summed
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

func (p *Exponent) MarshalBinary() (data []byte, err error) {
	var buf []byte
	buf = make([]byte, 0, p.Size())
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

func (p *Exponent) Size() int {
	return 4 + 32*len(p.coefficients)
}
