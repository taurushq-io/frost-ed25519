package common

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

var (
	ec elliptic.Curve
)

type ECPoint struct {
	x, y *big.Int
}

func NewECPoint(x, y *big.Int) (*ECPoint, error) {
	if !ec.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point is not on curve")
	}
	return &ECPoint{
		x: x,
		y: y,
	}, nil
}

func NewECPointBase() *ECPoint {
	return &ECPoint{
		x: ec.Params().Gx,
		y: ec.Params().Gy,
	}
}

func NewECPointBaseMult(k []byte) *ECPoint {
	x, y := ec.ScalarBaseMult(k)
	return &ECPoint{
		x: x,
		y: y,
	}
}

func (p *ECPoint) IsOnCurve() bool {
	return ec.IsOnCurve(p.x, p.y)
}

func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p.x)
}

func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func Modulus() *big.Int {
	return ec.Params().N
}

func Curve() elliptic.Curve {
	return ec
}

func SetCurve(curve elliptic.Curve) {
	ec = curve
}

func (p *ECPoint) Bytes() []byte {
	b := p.x.Bytes()
	b = append(b, p.y.Bytes()...)
	return b
}

func (p *ECPoint) Add(otherPoint *ECPoint) *ECPoint {
	x, y := ec.Add(p.x, p.y, otherPoint.x, otherPoint.y)
	return &ECPoint{
		x: x,
		y: y,
	}
}

func (p *ECPoint) ScalarMult(k []byte) *ECPoint {
	x, y := ec.ScalarMult(p.x, p.y, k)
	return &ECPoint{
		x: x,
		y: y,
	}
}

func IntToBytes(i int) []byte {
	i64 := int64(i)
	return []byte{
		byte(0xff & i64),
		byte(0xff & (i64 >> 8)),
		byte(0xff & (i64 >> 16)),
		byte(0xff & (i64 >> 24))}
}

func (p *ECPoint) Equals (otherPoint *ECPoint) bool {
	return p.x.Cmp(otherPoint.x) == 0 && p.y.Cmp(otherPoint.y) == 0
}