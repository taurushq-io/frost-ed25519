package frost

import (
	"errors"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

type Party struct {
	Index uint16
	Public *edwards25519.Point
}

type PartySecret struct {
	Index uint32
	Secret *edwards25519.Scalar
}


// ComputeLagrange computes the coefficient l_j(x)
//
// We assume that others does not contain any duplicates or self.
func ComputeLagrange(self uint32, allParties []uint32, ) (*edwards25519.Scalar, error) {

	var xJ, xM *edwards25519.Scalar
	var err error

	num := edwards25519.NewScalar()
	denum := edwards25519.NewScalar()

	xJ, err = common.NewScalarUInt32(self)
	if err != nil {
		return nil, err
	}

	for _, id := range allParties {
		if id == self {
			continue
		}

		xM, err = common.NewScalarUInt32(id)
		if err != nil {
			return nil, err
		}

		num.Multiply(num, xM) // num * xm
		xM.Subtract(xM, xJ)
		denum.Multiply(denum, xM) // denum * (xm - xj)
	}

	if denum.Equal(edwards25519.NewScalar()) == 1 {
		return nil, errors.New("others contained self")
	}
	denum.Invert(denum)
	num.Multiply(num, denum)
	return num, nil
}


func ComputeGroupKey(parties map[uint32]*Party) (*edwards25519.Point, error) {
	allPartyIDs := make([]uint32, 0, len(parties))
	for index := range parties {
		allPartyIDs = append(allPartyIDs, index)
	}

	groupKey := edwards25519.NewIdentityPoint()
	publicKeyShare := edwards25519.NewIdentityPoint()
	for index, party := range parties {
		coef, err := ComputeLagrange(index, allPartyIDs)
		if err != nil {
			return nil, fmt.Errorf("failed to compute Lagrange for %d: %w", index, err)
		}
		publicKeyShare.ScalarMult(coef, party.Public)
		groupKey.Add(groupKey, publicKeyShare)
	}

	return groupKey, nil
}