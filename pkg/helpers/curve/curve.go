package curve

import (
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
)

var (
	ec elliptic.Curve
)

func Modulus() *big.Int {
	return ec.Params().N
}

func Curve() elliptic.Curve {
	return ec
}

type ECPoint struct {
	x, y *big.Int
}

func NewECPoint(x, y *big.Int) (ECPoint, error) {
	if !ec.IsOnCurve(x, y) {
		return ECPoint{}, fmt.Errorf("point is not on curve")
	}
	return ECPoint{
		x: new(big.Int).Set(x),
		y: new(big.Int).Set(y),
	}, nil
}

// NewECPointInfinity returns the point at infinity, i.e. the identity.
func NewECPointInfinity() ECPoint {
	zero := new(big.Int)
	return NewECPointBaseMult(zero.Bytes())
}

func NewECPointBase() ECPoint {
	return ECPoint{
		x: new(big.Int).Set(ec.Params().Gx),
		y: new(big.Int).Set(ec.Params().Gy),
	}
}

func NewECPointBaseMult(k []byte) ECPoint {
	x, y := ec.ScalarBaseMult(k)
	return ECPoint{
		x: x,
		y: y,
	}
}

func (p ECPoint) IsOnCurve() bool {
	return ec.IsOnCurve(p.x, p.y)
}

func (p ECPoint) X() *big.Int {
	return new(big.Int).Set(p.x)
}

func (p ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func SetCurve(curve elliptic.Curve) {
	ec = curve
}

func (p ECPoint) Bytes() []byte {
	b := p.x.Bytes()
	b = append(b, p.y.Bytes()...)
	return b
}

func (p ECPoint) Add(otherPoint ECPoint) ECPoint {
	x, y := ec.Add(p.x, p.y, otherPoint.x, otherPoint.y)
	return ECPoint{
		x: x,
		y: y,
	}
}

func (p ECPoint) ScalarMult(k []byte) ECPoint {
	x, y := ec.ScalarMult(p.x, p.y, k)
	return ECPoint{
		x: x,
		y: y,
	}
}

func (p *ECPoint) Equals(otherPoint ECPoint) bool {
	return p.x.Cmp(otherPoint.x) == 0 && p.y.Cmp(otherPoint.y) == 0
}

func (p ECPoint) Write(w io.Writer) (n int, err error) {
	n, err = w.Write(p.Bytes())
	return
}
