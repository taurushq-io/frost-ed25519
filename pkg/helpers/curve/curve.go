package curve



type Curve interface {
	String() string
	Scalar() Scalar
	Point() Point
}

type Scalar interface {
	Zero() Scalar
	One() Scalar

	// Add sets s = n + y mod l, and returns s.
	Add(x, y Scalar) Scalar
	// Subtract sets s = n - y mod l, and returns s.
	Subtract(x, y Scalar) Scalar
	// Negate sets s = -n mod l, and returns s.
	Negate(x Scalar) Scalar
	// Multiply sets s = n * y mod l, and returns s.
	Multiply(x, y Scalar) Scalar

	// Set sets s = n, and returns s.
	Set(x Scalar) Scalar

	// Invert sets s to the inverse of a nonzero scalar v, and returns s.
	//
	// If t is zero, Invert will panic.
	Invert(t Scalar) Scalar

	// EncodeLen returns the number of bytes required to represent the Scalar
	EncodeLen() int
	// Encode appends the 32 bytes canonical encoding of e to b
	// and returns the result.
	Encode(d []byte) []byte
	// Decode sets e to the decoded value of in. If in is not a 32 byte canonical
	// encoding, Decode returns an error, and the receiver is unchanged.
	Decode(in []byte) (Scalar, error)

	Equal(t Scalar) int

	Rand() (Scalar, error)
}

type Point interface {
	Base() Point
	Infinity() Point

	// Set sets v = u, and returns v.
	Set(u Point) Point

	// EncodeLen returns the number of bytes required to represent the Point
	EncodeLen() int
	// Encode appends the 32 bytes canonical encoding of e to b
	// and returns the result.
	Encode(d []byte) []byte
	// Decode sets e to the decoded value of in. If in is not a 32 byte canonical
	// encoding, Decode returns an error, and the receiver is unchanged.
	Decode(in []byte) (Point, error)

	Equal(u Point) int

	// Add sets v = p + q, and returns v.
	Add(p, q Point) Point
	// Subtract sets v = p - q, and returns v.
	Subtract(p, q Point) Point
	// Negate sets v = -p, and returns v.
	Negate(p Point) Point

	// ScalarBaseMult sets v = n * B, where B is the canonical generator, and
	// returns v.
	//
	// The scalar multiplication is done in constant time.
	ScalarBaseMult(x Scalar) Point
	// ScalarMult sets v = n * q, and returns v.
	//
	// The scalar multiplication is done in constant time.
	ScalarMult(x Scalar, q Point) Point

	//// MultiScalarMult sets v = sum(scalars[i] * points[i]), and returns v.
	////
	//// Execution time depends only on the lengths of the two slices, which must match.
	//MultiScalarMult(scalars []Scalar, points []Point) Point
}







//var (
//	ec elliptic.Curve
//)
//
//func Modulus() *big.Int {
//	return ec.Params().N
//}
//
//func Curve() elliptic.Curve {
//	return ec
//}
//
//type ECPoint struct {
//	n, y *big.Int
//}
//
//func NewECPoint(n, y *big.Int) (ECPoint, error) {
//	if !ec.IsOnCurve(n, y) {
//		return ECPoint{}, fmt.Errorf("point is not on curve")
//	}
//	return ECPoint{
//		n: new(big.Int).Set(n),
//		y: new(big.Int).Set(y),
//	}, nil
//}
//
//// NewECPointInfinity returns the point at infinity, i.e. the identity.
//func NewECPointInfinity() ECPoint {
//	zero := new(big.Int)
//	return NewECPointBaseMult(zero.Bytes())
//}
//
//func NewECPointBase() ECPoint {
//	return ECPoint{
//		n: new(big.Int).Set(ec.Params().Gx),
//		y: new(big.Int).Set(ec.Params().Gy),
//	}
//}
//
//func NewECPointBaseMult(k []byte) ECPoint {
//	n, y := ec.ScalarBaseMult(k)
//	return ECPoint{
//		n: n,
//		y: y,
//	}
//}
//
//func (p ECPoint) IsOnCurve() bool {
//	return ec.IsOnCurve(p.n, p.y)
//}
//
//func (p ECPoint) X() *big.Int {
//	return new(big.Int).Set(p.n)
//}
//
//func (p ECPoint) Y() *big.Int {
//	return new(big.Int).Set(p.y)
//}
//
//func SetCurve(curve elliptic.Curve) {
//	ec = curve
//}
//
//func (p ECPoint) Bytes() []byte {
//	b := p.n.Bytes()
//	b = append(b, p.y.Bytes()...)
//	return b
//}
//
//func (p ECPoint) Add(otherPoint ECPoint) ECPoint {
//	n, y := ec.Add(p.n, p.y, otherPoint.n, otherPoint.y)
//	return ECPoint{
//		n: n,
//		y: y,
//	}
//}
//
//func (p ECPoint) ScalarMult(k []byte) ECPoint {
//	n, y := ec.ScalarMult(p.n, p.y, k)
//	return ECPoint{
//		n: n,
//		y: y,
//	}
//}
//
//func (p *ECPoint) Equals(otherPoint ECPoint) bool {
//	return p.n.Cmp(otherPoint.n) == 0 && p.y.Cmp(otherPoint.y) == 0
//}
//
//func (p ECPoint) Write(w io.Writer) (n int, err error) {
//	n, err = w.Write(p.Bytes())
//	return
//}
