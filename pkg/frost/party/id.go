package party

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// ByteSize is the number of bytes required to store and ID or Size
const ByteSize = 2

// MAX is the maximum integer that can represent a party.
// It can be used to bound the number of parties, and the maximum integer value
// an ID can be.
const MAX = (1 << (ByteSize * 8)) - 1

// ID represents the identifier of a particular party.
// A parti
type ID uint16

// Size is an alias for ID that allows us to differentiate between a party's ID and the threshold for example.
type Size = ID

// setScalar returns the corresponding ristretto.Scalar
func (p ID) setScalar(s *ristretto.Scalar) *ristretto.Scalar {
	bytes := make([]byte, 32)

	binary.LittleEndian.PutUint16(bytes, uint16(p))

	_, err := s.SetCanonicalBytes(bytes[:])
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to set uint32 Scalar: %w", err))
	}
	return s
}

// Scalar returns the corresponding ristretto.Scalar
func (p ID) Scalar() *ristretto.Scalar {
	// We outline the function so that s is not allocated on the heap
	var s ristretto.Scalar
	return p.setScalar(&s)
}

// Bytes returns a []byte slice of length party.ByteSize
func (p ID) Bytes() []byte {
	bytes := make([]byte, ByteSize)

	binary.BigEndian.PutUint16(bytes, uint16(p))
	return bytes
}

// String returns a base 10 representation of ID
func (p ID) String() string {
	return strconv.FormatUint(uint64(p), 10)
}

// FromBytes reads the first party.ByteSize bytes from b and creates an ID from it.
// Returns an error if b is too small to hold an ID.
func FromBytes(b []byte) (ID, error) {
	if len(b) < ByteSize {
		return 0, errors.New("party.FromBytes: b is not long enough to hold an ID")
	}
	return ID(binary.BigEndian.Uint16(b)), nil
}

// RandIDn returns, as an ID, a non-negative pseudo-random number in [1,n]
// from the default Source.
// It panics if n <= 0.
func RandIDn(n Size) ID {
	return ID(rand.Int31n(int32(n))) + 1
}

// RandID returns a pseudo-random value as a ID
// from the default Source.
func RandID() ID {
	return ID(rand.Int31n(MAX)) + 1
}

// MarshalText implements encoding/TextMarshaler interface
func (p ID) MarshalText() (text []byte, err error) {
	return []byte(strconv.FormatUint(uint64(p), 10)), nil
}

// UnmarshalText implements encoding/TextMarshaler interface
func (p *ID) UnmarshalText(text []byte) error {
	id, err := strconv.ParseUint(string(text), 10, 16)
	if err != nil {
		return err
	}
	*p = ID(id)
	return nil
}

// Lagrange gives the Lagrange coefficient l_j(x) for x = 0.
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//			( x  - x_0) ... ( x  - x_k)
// l_j(x) =	---------------------------
//			(x_j - x_0) ... (x_j - x_k)
//
//			        x_0 ... x_k
// l_j(0) =	---------------------------
//			(x_0 - x_j) ... (x_k - x_j)
func (p ID) Lagrange(ids IDSlice) *ristretto.Scalar {
	var one, num, denum, xM, xJ ristretto.Scalar
	_, _ = one.SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	num.Set(&one)
	denum.Set(&one)

	p.setScalar(&xJ)

	for _, id := range ids {
		if id == p {
			continue
		}

		id.setScalar(&xM)

		// num = x_0 * ... * x_k
		num.Multiply(&num, &xM) // num * xM

		// denum = (x_0 - x_j) ... (x_k - x_j)
		xM.Subtract(&xM, &xJ)       // = xM - xJ
		denum.Multiply(&denum, &xM) // denum * (xm - xj)
	}

	denum.Invert(&denum)
	num.Multiply(&num, &denum)
	return &num
}
