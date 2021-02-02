package frost

import (
	"errors"
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

type Party struct {
	Index  uint32
	Public *edwards25519.Point
}

type PartySecret struct {
	Index  uint32
	Secret *edwards25519.Scalar
}

// ComputeLagrange gives the Lagrange coefficient l_j(x)
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
func ComputeLagrange(self uint32, allParties []uint32) *edwards25519.Scalar {
	var xJ, xM *edwards25519.Scalar

	num := common.NewScalarUInt32(uint32(1))
	denum := common.NewScalarUInt32(uint32(1))

	xJ = common.NewScalarUInt32(self)

	for _, id := range allParties {
		if id == self {
			continue
		}

		xM = common.NewScalarUInt32(id)

		// num = x_0 * ... * x_k
		num = num.Multiply(num, xM) // num * xM

		// denum = (x_0 - x_j) ... (x_k - x_j)
		xM = xM.Subtract(xM, xJ)          // = xM - xJ
		denum = denum.Multiply(denum, xM) // denum * (xm - xj)
	}

	// This should not happen since xM!=xJ
	if denum.Equal(edwards25519.NewScalar()) == 1 {
		panic(errors.New("others contained self"))
	}
	denum.Invert(denum)
	num.Multiply(num, denum)
	return num
}

func ComputeGroupKey(parties map[uint32]*Party) (*PublicKey, error) {
	allPartyIDs := make([]uint32, 0, len(parties))
	for index := range parties {
		allPartyIDs = append(allPartyIDs, index)
	}

	groupKey := edwards25519.NewIdentityPoint()
	tmp := new(edwards25519.Point)
	for _, party := range parties {
		coef := ComputeLagrange(party.Index, allPartyIDs)

		// tmp = [lambda] A = [lambda * sk] B
		tmp.ScalarMult(coef, party.Public)

		if tmp.Equal(party.Public) != 1 {
			print("")
		}
		groupKey.Add(groupKey, tmp)
	}

	return &PublicKey{pk: *groupKey}, nil
}