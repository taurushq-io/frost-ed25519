package vss

import (
	"errors"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"
	"math/big"
)

type (
	Share struct {
		partyId      common.Party
		threshold    uint32
		PrivateShare *big.Int
	}

	Commitments = PolynomialExp
)

// vss.New generates a Feldman VSS shares, and commitments for a given secret value a0.
// If a0 is nil, then the secret is chosen randomly.
func New(secret *big.Int, threshold uint32, parties []common.Party) ([]Share, Commitments, error) {
	n := uint32(len(parties))
	if threshold >= n {
		return nil, nil, errors.New("wrong threshold")
	}

	polynomial, err := NewRandomPolynomial(threshold, secret)
	if err != nil {
		return nil, nil, errors.New("failed to generate polynomial")
	}
	polynomialExp := ConvertPolynomial(polynomial)

	// for each party, generate their Share as f(partyId)
	shares := make([]Share, n)
	for i, id := range parties {
		if id == 0 {
			return nil, nil, errors.New("a party cannot have index 0")
		}
		Id := new(big.Int).SetInt64(int64(id))
		shares[i] = Share{
			partyId:      id,
			threshold:    threshold,
			PrivateShare: polynomial.Evaluate(Id),
		}
	}
	return shares, polynomialExp, nil
}

func (s Share) Verify(party common.Party, commitments Commitments) bool {
	if party != s.partyId {
		return false
	}
	shareExp := curve.NewECPointBaseMult(s.PrivateShare.Bytes())
	otherShareExp := commitments.Evaluate(new(big.Int).SetInt64(int64(s.partyId)))
	return shareExp.Equals(otherShareExp)
}

// GetPublicKeys generates all public key shares using the commitments from the n VSS rounds.
// The commitments represent the individual Shamir polynomials, so we add them up to obtain the Shamir polynomial
// of the final shared secret. We can then evaluate this polynomial (in the exponent) for each party and generate their public key.
func GetPublicKeys(parties []common.Party, commitments []Commitments) ([]common.PublicKeyShare, error) {
	polynomialSum, err := SumPolynomialExp(commitments)
	if err != nil {
		return nil, fmt.Errorf("failed to sum polynomials: %w", err)
	}
	publicKeys := make([]common.PublicKeyShare, len(parties))
	for i, party := range parties {
		publicKeys[i] = common.PublicKeyShare{
			Party:     party,
			PublicKey: polynomialSum.Evaluate(new(big.Int).SetInt64(int64(party))),
		}
	}
	return publicKeys, nil
}
