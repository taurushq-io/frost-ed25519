package party

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"

	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// IDByteSize is the number of bytes required to store and ID or Size
const IDByteSize = 2

// _MAX is the maximum integer that can represent a party.
// It can be used to bound the number of parties, and the maximum integer value
// an ID can be.
const _MAX = uint64(math.MaxUint32)

// ID represents the identifier of a particular party, encoded as a 16 bit unsigned integer.
// The ID 0 is considered invalid.
type ID uint16

// Size is an alias for ID that allows us to differentiate between a party's ID and the threshold for example.
type Size = ID

// Scalar returns the corresponding ristretto.Scalar
func (id ID) Scalar() *ristretto.Scalar {
	var s ristretto.Scalar
	bytes := make([]byte, 32)

	binary.LittleEndian.PutUint16(bytes, uint16(id))

	_, err := s.SetCanonicalBytes(bytes[:])
	if err != nil {
		panic(fmt.Errorf("edwards25519: failed to set uint32 Scalar: %w", err))
	}
	return &s
}

// Bytes returns a []byte slice of length party.IDByteSize
func (id ID) Bytes() []byte {
	bytes := make([]byte, IDByteSize)

	binary.BigEndian.PutUint16(bytes, uint16(id))
	return bytes
}

// String returns a base 10 representation of ID
func (id ID) String() string {
	return strconv.FormatUint(uint64(id), 10)
}

// FromBytes reads the first party.IDByteSize bytes from b and creates an ID from it.
// Returns an error if b is too small to hold an ID
func FromBytes(b []byte) (ID, error) {
	if len(b) < IDByteSize {
		return 0, errors.New("party.FromBytes: b is not long enough to hold an ID")
	}
	id := ID(binary.BigEndian.Uint16(b))
	return id, nil
}

// RandID returns a pseudo-random value as a ID
// from the default Source.
func RandID() ID {
	id := rand.Int31n(math.MaxUint16 + 1)
	if id == 0 {
		return ID(id + 1)
	}
	return ID(id)
}

// MarshalText implements encoding/TextMarshaler interface
func (id ID) MarshalText() (text []byte, err error) {
	return []byte(strconv.FormatUint(uint64(id), 10)), nil
}

// UnmarshalText implements encoding/TextMarshaler interface
// Returns an error when the encoded text is too large
func (id *ID) UnmarshalText(text []byte) error {
	idUint, err := strconv.ParseUint(string(text), 10, 16)
	if err != nil {
		return fmt.Errorf("party.ID: UnmarshalText: %v", err)
	}
	if idUint > _MAX {
		return errors.New("party.ID: UnmarshalText: party ID overflows")
	}
	*id = ID(idUint)
	return nil
}

// Lagrange gives the Lagrange coefficient lⱼ(x) for x = 0.
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//			( x  - x₀) ... ( x  - xₖ)
// lⱼ(x) =	---------------------------
//			(xⱼ - x₀) ... (xⱼ - xₖ)
//
//			        x₀ ... xₖ
// lⱼ(0) =	---------------------------
//			(x₀ - xⱼ) ... (xₖ - xⱼ)
//
// returns an error if id is not included in partyIDs
func (id ID) Lagrange(partyIDs IDSlice) (*ristretto.Scalar, error) {
	if id == 0 {
		return nil, errors.New("party.ID: Lagrange: id was 0 (invalid)")
	}
	var one, num, denum, xM, xJ ristretto.Scalar

	// we can't use scalar.NewScalarUInt32() since that would cause an import cycle
	_, _ = one.SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	num.Set(&one)
	denum.Set(&one)

	xJ = *id.Scalar()

	foundSelfInIDs := false
	for _, partyID := range partyIDs {
		if partyID == id {
			foundSelfInIDs = true
			continue
		}

		xM = *partyID.Scalar()

		// num = x₀ * ... * xₖ
		num.Multiply(&num, &xM) // num * xM

		// denum = (x₀ - xⱼ) ... (xₖ - xⱼ)
		xM.Subtract(&xM, &xJ)       // = xM - xJ
		denum.Multiply(&denum, &xM) // denum * (xm - xj)
	}
	if !foundSelfInIDs {
		return nil, errors.New("party.ID: Lagrange: partyIDs does not containd id")
	}
	// check against 0
	if denum.Equal(ristretto.NewScalar()) == 1 {
		return nil, errors.New("party.ID: Lagrange: denominator was 0")
	}

	denum.Invert(&denum)
	num.Multiply(&num, &denum)
	return &num, nil
}
