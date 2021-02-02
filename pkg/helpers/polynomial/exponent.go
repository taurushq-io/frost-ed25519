package polynomial

import (
	"bytes"
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
	for i, coefficient := range polynomialExp.coefficients {
		coefficient.ScalarBaseMult(&polynomial.coefficients[i])
	}
	return polynomialExp
}

// evaluatePolynomial evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Exponent) Evaluate(index uint32) *edwards25519.Point {
	x := common.NewScalarUInt32(index)
	result := edwards25519.NewIdentityPoint()

	tmp := new(edwards25519.Point)

	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// B_n-1 = [x]B_n  + A_n-1
		tmp.ScalarMult(x, result)
		tmp.Add(tmp, &p.coefficients[i])
		result.Add(result, tmp)
	}
	return result
}

func (p *Exponent) Degree() uint32 {
	return uint32(len(p.coefficients)) - 1
}


func (p *Exponent) Size() int {
	return len(p.coefficients)
}


func Sum(polynomials []*Exponent) *Exponent {
	degree := polynomials[0].Degree()
	size := polynomials[0].Size()
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

func (p *Exponent) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, 1 + 32 * len(p.coefficients))
	Buf := bytes.NewBuffer(buf)
	binary.Write(Buf, binary.BigEndian, p.Degree())
	for i := 0; i < len(p.coefficients); i++ {
		Buf.Write(p.coefficients[i].Bytes())
	}
	return Buf.Bytes(), nil
}

func (p *Exponent) UnmarshalBinary(data []byte) error {
	degree := binary.BigEndian.Uint32(data[:4])
	p.coefficients = make([]edwards25519.Point, degree + 1)

	remaining := data[4:]
	count := len(remaining)
	if count % 32 != 0 {
		return errors.New("length of data is wrong")
	}
	if count / 32 != p.Size() {
		return errors.New("wrong number of coefficients embedded")
	}
	var err error
	for i := 0; i < p.Size(); i++ {
		NextScalarBytes := remaining[i*32:(i+1)*32]
		_, err = p.coefficients[i].SetBytes(NextScalarBytes)
		if err != nil {
			return err
		}
	}
	return nil
}