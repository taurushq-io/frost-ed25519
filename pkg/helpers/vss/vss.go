package vss

import (
	"errors"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

type (
	VSS struct {
		Threshold, ShareCount uint32
		Commitments           []*edwards25519.Point
	}
	Shares map[common.Party]*edwards25519.Scalar
)

func NewVSS(t uint32, secret *edwards25519.Scalar, parties []common.Party) (vss *VSS, shares Shares, err error) {
	polynomial, err := samplePolynomial(t, secret)
	if err != nil {
		return nil, nil, err
	}

	shares, err = generateShares(polynomial, parties)
	if err != nil {
		return nil, nil, err
	}

	n := uint32(len(parties))

	commitment := computeCommitments(polynomial)

	vss = &VSS{
		Threshold:   t,
		ShareCount:  n,
		Commitments: commitment,
	}

	return vss, shares, nil
}

func (vss *VSS) Verify(threshold, partyCount uint32) bool {
	if vss.Threshold != threshold || vss.ShareCount != partyCount {
		return false
	}

	return true
}

// VerifyShare performs the Feldman verification of the received share, using the commitments.
func (vss *VSS) VerifyShare(share *edwards25519.Scalar, index common.Party) bool {
	err := verifyCommitments(vss.Commitments, share, index)
	if err != nil {
		return false
	}
	return true
}

// PublicKey returns the public key associated to the VSS. It is simply the f(0)•G.
func (vss *VSS) PublicKey() *edwards25519.Point {
	return vss.Commitments[0]
}

// PublicKey returns the public key associated to the VSS. It is simply the f(0)•G.
func (vss *VSS) PublicKeys(parties []common.Party) map[common.Party]*edwards25519.Point {
	keys := make(map[common.Party]*edwards25519.Point, len(parties))

	for _, party := range parties {
		keys[party] = evaluatePolynomialExponent(vss.Commitments, party)
	}

	return keys
}

// SumVSS takes a map (party, VSS) and sums the commitments in order to obtain the VSS of the final key
// It is assumed that this party's VSS is included in the map.
// Returns an error if anything is wrong.
func SumVSS(vssMap map[common.Party]*VSS, threshold, parties uint32) (*VSS, error) {
	if len(vssMap) != int(parties) {
		return nil, errors.New("invalid number of vss structs given")
	}
	newVSS := &VSS{
		Threshold:   threshold,
		ShareCount:  parties,
		Commitments: make([]*edwards25519.Point, threshold+1),
	}

	infinity := edwards25519.NewIdentityPoint()
	// set all commitments to ∞ initially
	for i := range newVSS.Commitments {
		newVSS.Commitments[i] = new(edwards25519.Point).Set(infinity)
	}

	for index, otherVss := range vssMap {
		if otherVss.ShareCount != parties || otherVss.Threshold != threshold {
			// TODO make proper error
			return nil, fmt.Errorf("SumVSS: index=%d invalid params n=%d, t=%d", index.UInt32(), otherVss.ShareCount, otherVss.Threshold)
		}
		if len(otherVss.Commitments) != int(threshold)+1 {
			// TODO make proper error
			return nil, fmt.Errorf("SumVSS: index=%d wrong number of commitments", index.UInt32())
		}

		// Add the commitments
		for deg, coef := range newVSS.Commitments {
			coef.Add(coef, otherVss.Commitments[deg])
		}
	}

	return newVSS, nil

}
