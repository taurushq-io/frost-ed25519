package curve

import (
	"filippo.io/edwards25519"
	"crypto/rand"
)

type Ed25519Curve struct {
}

func (c *Ed25519Curve) String() string {
	return "Ed25519"
}

func (c *Ed25519Curve) Scalar() Scalar {
	return &Ed25519Scalar{}
}

func (c *Ed25519Curve) Point() Point {
	return &Ed25519Point{}
}

type Ed25519Point struct {
	point *edwards25519.Point
}

func (v *Ed25519Point) Base() Point {
	v.point = edwards25519.NewGeneratorPoint()
	return v
}

func (v *Ed25519Point) Infinity() Point {
	v.point = edwards25519.NewIdentityPoint()
	return v
}

func (v *Ed25519Point) Set(u Point) Point {
	v.point.Set(u.(*Ed25519Point).point)
	return v
}

func (v *Ed25519Point) EncodeLen() int {
	return 32
}

func (v *Ed25519Point) Encode(d []byte) []byte {
	return append(d, v.point.Bytes()...)
}

func (v *Ed25519Point) Decode(in []byte) (Point, error) {
	tmp, err := v.point.SetBytes(in)
	if err != nil {
		return nil, err
	}
	v.point = tmp
	return v, nil
}

func (v *Ed25519Point) Equal(u Point) int {
	return v.point.Equal(u.(*Ed25519Point).point)
}

func (v *Ed25519Point) Add(p, q Point) Point {
	v.point = v.point.Add(p.(*Ed25519Point).point, q.(*Ed25519Point).point)
	return v
}

func (v *Ed25519Point) Subtract(p, q Point) Point {
	v.point = v.point.Subtract(p.(*Ed25519Point).point, q.(*Ed25519Point).point)
	return v
}

func (v *Ed25519Point) Negate(p Point) Point {
	v.point = v.point.Negate(p.(*Ed25519Point).point)
	return v
}

func (v *Ed25519Point) ScalarBaseMult(x Scalar) Point {
	v.point = v.point.ScalarBaseMult(x.(*Ed25519Scalar).scalar)
	return v
}

func (v *Ed25519Point) ScalarMult(x Scalar, q Point) Point {
	v.point = v.point.ScalarMult(x.(*Ed25519Scalar).scalar, q.(*Ed25519Point).point)
	return v
}

type Ed25519Scalar struct {
	scalar *edwards25519.Scalar
}

func (s *Ed25519Scalar) Zero() Scalar {
	s.scalar = edwards25519.NewScalar()
	return s
}

func (s *Ed25519Scalar) One() Scalar {
	s.scalar, _ = s.scalar.SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	return s
}

func (s *Ed25519Scalar) Add(x, y Scalar) Scalar {
	s.scalar = s.scalar.Add(x.(*Ed25519Scalar).scalar, y.(*Ed25519Scalar).scalar)
	return s
}

func (s *Ed25519Scalar) Subtract(x, y Scalar) Scalar {
	s.scalar = s.scalar.Subtract(x.(*Ed25519Scalar).scalar, y.(*Ed25519Scalar).scalar)
	return s
}

func (s *Ed25519Scalar) Negate(x Scalar) Scalar {
	s.scalar = s.scalar.Negate(x.(*Ed25519Scalar).scalar)
	return s
}

func (s *Ed25519Scalar) Multiply(x, y Scalar) Scalar {
	s.scalar = s.scalar.Multiply(x.(*Ed25519Scalar).scalar, y.(*Ed25519Scalar).scalar)
	return s
}

func (s *Ed25519Scalar) Set(x Scalar) Scalar {
	s.scalar = s.scalar.Set(x.(*Ed25519Scalar).scalar)
	return s
}

func (s *Ed25519Scalar) Invert(t Scalar) Scalar {
	s.scalar = s.scalar.Invert(t.(*Ed25519Scalar).scalar)
	return s
}

func (s *Ed25519Scalar) EncodeLen() int {
	return 32
}

func (s *Ed25519Scalar) Encode(d []byte) []byte {
	return append(d, s.scalar.Bytes()...)
}

func (s *Ed25519Scalar) Decode(in []byte) (Scalar, error) {
	tmp, err := s.scalar.SetCanonicalBytes(in)
	if err != nil {
		return nil, err
	}
	s.scalar = tmp
	return s, nil
}

func (s *Ed25519Scalar) Equal(t Scalar) int {
	return s.scalar.Equal(t.(*Ed25519Scalar).scalar)
}

func (s *Ed25519Scalar) Rand() (Scalar, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	s.scalar = s.scalar.SetUniformBytes(b)
	return s, nil
}

