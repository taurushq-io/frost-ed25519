package curve

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

type PCurve struct {
	curve elliptic.Curve
}

func (c *PCurve) String() string {
	return c.curve.Params().Name
}

func (c *PCurve) Scalar() Scalar {
	return &PScalar{
		n:     new(big.Int),
		curve: c.curve,
	}
}

func (c *PCurve) Point() Point {
	return &ECPoint{
		curve:  c.curve,
		coords: [2]*big.Int{nil, nil},
	}
}



type PScalar struct {
	n     *big.Int
	curve elliptic.Curve
}

func (s *PScalar) Zero() Scalar {
	s.n.SetInt64(0)
	return s
}

func (s *PScalar) One() Scalar {
	s.n.SetInt64(1)
	return s
}

func (s *PScalar) Add(x, y Scalar) Scalar {
	s.n.Add(x.(*PScalar).n, y.(*PScalar).n)
	s.n.Mod(s.n, s.curve.Params().P)
	return s
}

func (s *PScalar) Subtract(x, y Scalar) Scalar {
	s.n.Sub(x.(*PScalar).n, y.(*PScalar).n)
	s.n.Mod(s.n, s.curve.Params().P)
	return s
}

func (s *PScalar) Negate(x Scalar) Scalar {
	s.n.Neg(x.(*PScalar).n)
	s.n.Mod(s.n, s.curve.Params().P)
	return s
}

func (s *PScalar) Multiply(x, y Scalar) Scalar {
	s.n.Mul(x.(*PScalar).n, y.(*PScalar).n)
	s.n.Mod(s.n, s.curve.Params().P)
	return s
}

func (s *PScalar) Set(x Scalar) Scalar {
	s.n.Set(x.(*PScalar).n)
	return s
}

func (s *PScalar) Invert(t Scalar) Scalar {
	temp := s.n.ModInverse(t.(*PScalar).n, s.curve.Params().P)
	if temp == nil {
		return nil
	}
	return s
}

func (s *PScalar) EncodeLen() int {
	return (s.curve.Params().BitSize + 7) / 8
}

func (s *PScalar) Encode(d []byte) []byte {
	buf := make([]byte, s.EncodeLen())
	buf = s.n.FillBytes(buf)
	return append(d, buf...)
}

func (s *PScalar) Decode(in []byte) (Scalar, error) {
	temp := new(big.Int).SetBytes(in)
	if temp.Cmp(s.curve.Params().P) != -1 {
		return nil, errors.New("input was too large")
	}
	s.n.Set(temp)
	return s, nil
}

func (s *PScalar) Equal(t Scalar) int {
	if s.n.Cmp(t.(*PScalar).n) == 0 {
		return 1
	}
	return 0
}

func (s *PScalar) Rand() (Scalar, error) {
	temp, err := rand.Int(rand.Reader, s.curve.Params().P)
	if err != nil {
		return nil, err
	}
	s.n.Set(temp)
	return s, nil
}

type ECPoint struct {
	curve elliptic.Curve
	coords [2]*big.Int
}

func (v *ECPoint) Base() Point {
	params := v.curve.Params()
	v.coords[0].Set(params.Gx)
	v.coords[1].Set(params.Gy)
	return v
}

func (v *ECPoint) Infinity() Point {
	v.coords[0].SetInt64(0)
	v.coords[1].SetInt64(0)
	return v
}

func (v *ECPoint) Set(u Point) Point {
	up := u.(*ECPoint)
	v.coords[0].Set(up.coords[0])
	v.coords[1].Set(up.coords[1])
	return v
}

func (v *ECPoint) EncodeLen() int {
	return 1+2*((v.curve.Params().BitSize + 7) / 8)
}

func (v *ECPoint) Encode(d []byte) []byte {
	return append(d, elliptic.Marshal(v.curve, v.coords[0], v.coords[1])...)
}

func (v *ECPoint) Decode(in []byte) (Point, error) {
	newX, newY := elliptic.Unmarshal(v.curve, in)
	if newX == nil {
		return nil, errors.New("failed to unmarshal")
	}
	v.coords[0].Set(newX)
	v.coords[1].Set(newY)
	return v, nil
}

func (v *ECPoint) Equal(u Point) int {
	if v.curve == u.(*ECPoint).curve && v.coords[0].Cmp(u.(*ECPoint).coords[0]) == 0 && v.coords[1].Cmp(u.(*ECPoint).coords[1]) == 0 {
		return 1
	}
	return 0
}

func (v *ECPoint) Add(p, q Point) Point {
	v.coords[0], v.coords[1] = v.curve.Add(p.(*ECPoint).coords[0], p.(*ECPoint).coords[1], q.(*ECPoint).coords[0], q.(*ECPoint).coords[1])
	return v
}

func (v *ECPoint) Subtract(p, q Point) Point {
	negQy := new(big.Int).Neg(q.(*ECPoint).coords[1])
	negQy.Add(negQy, v.curve.Params().P)

	v.coords[0], v.coords[1] = v.curve.Add(p.(*ECPoint).coords[0], p.(*ECPoint).coords[1], q.(*ECPoint).coords[0], negQy)
	return v
}

func (v *ECPoint) Negate(p Point) Point {
	v.coords[0].Set(p.(*ECPoint).coords[0])

	v.coords[1].Set(p.(*ECPoint).coords[1])
	v.coords[1].Neg(v.coords[1])
	v.coords[1].Add(v.coords[1], v.curve.Params().P)
	return v
}

func (v *ECPoint) ScalarBaseMult(x Scalar) Point {
	v.coords[0], v.coords[1] = v.curve.ScalarBaseMult(x.(*PScalar).n.Bytes())
	return v
}

func (v *ECPoint) ScalarMult(x Scalar, q Point) Point {
	v.coords[0], v.coords[1] = v.curve.ScalarMult(q.(*ECPoint).coords[0], q.(*ECPoint).coords[1], x.(*PScalar).n.Bytes())
	return v
}


