package party

import (
	"errors"
	"sort"

	"filippo.io/edwards25519"
)

// Set holds a set of party.ID s that can be queried in various ways.
type Set struct {
	set   map[ID]bool
	slice []ID
}

func NewSet(partyIDs []ID) (*Set, error) {
	n := len(partyIDs)
	s := &Set{
		set:   make(map[ID]bool, n),
		slice: make([]ID, 0, n),
	}
	for _, id := range partyIDs {
		if id == 0 {
			return nil, errors.New("IDs in allPartyIDs cannot be 0")
		}
		if !s.set[id] {
			s.set[id] = true
			s.slice = append(s.slice, id)
		}
	}
	sort.Slice(s.slice, func(i, j int) bool { return s.slice[i] < s.slice[j] })
	return s, nil
}

func (s *Set) Contains(partyIDs ...ID) bool {
	for _, id := range partyIDs {
		if !s.set[id] {
			return false
		}
	}
	return true
}

func (s *Set) Sorted() []ID {
	return s.slice
}

func (s *Set) Take(n Size) []ID {
	if int(n) > len(s.set) {
		n = Size(len(s.set))
	}
	partyIDs := make([]ID, 0, n)
	for id := range s.set {
		partyIDs = append(partyIDs, id)
		if len(partyIDs) == int(n) {
			break
		}
	}
	return partyIDs
}

func (s *Set) N() Size {
	return Size(len(s.set))
}

func (s *Set) Equal(otherSet *Set) bool {
	if len(s.set) != len(otherSet.set) {
		return false
	}
	for id := range s.set {
		if !otherSet.set[id] {
			return false
		}
	}
	return true
}

func (s *Set) IsSubsetOf(otherSet *Set) bool {
	return otherSet.Contains(s.slice...)
}

func (s *Set) Range() map[ID]bool {
	return s.set
}

//  Lagrange gives the Lagrange coefficient l_j(x)
// for x = 0, since we are only interested in interpolating
// the constant coefficient.
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
func (s *Set) Lagrange(partyID ID) (*edwards25519.Scalar, error) {
	if !s.Contains(partyID) {
		return nil, errors.New("the Set must contain")
	}

	denum := ID(1).Scalar()
	num := ID(1).Scalar()

	xJ := partyID.Scalar()

	for _, id := range s.slice {
		if id == partyID {
			continue
		}

		xM := id.Scalar()

		// num = x_0 * ... * x_k
		num.Multiply(num, xM) // num * xM

		// denum = (x_0 - x_j) ... (x_k - x_j)
		xM.Subtract(xM, xJ)       // = xM - xJ
		denum.Multiply(denum, xM) // denum * (xm - xj)
	}

	// This should not happen since xM!=xJ
	if denum.Equal(edwards25519.NewScalar()) == 1 {
		return nil, errors.New("partyIDs contained idx")
	}

	denum.Invert(denum)
	num.Multiply(num, denum)
	return num, nil
}
