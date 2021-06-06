package eddsa

import (
	"encoding/json"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// Public holds the public keys generated during a key generation protocol.
// It also stores the associated party list, the threshold used and the full group key.
type Public struct {
	// PartyIDs is a party.Set that represents all parties with a share.
	PartyIDs party.IDSlice

	// Threshold returns the integer which defines the maximum number of parties that may be corrupted
	Threshold party.Size

	// Shares maps ID's to the threshold Shamir shares of the public GroupKey
	Shares map[party.ID]*ristretto.Element

	// GroupKey is the group's public key
	// It is the result of interpolating the Shamir shares at 0
	GroupKey *PublicKey
}

// NewPublic creates a Public structure given a map of public key shares as ristretto.Element, the threshold used.
func NewPublic(shares map[party.ID]*ristretto.Element, threshold party.Size) (*Public, error) {
	n := len(shares)
	IDs := make([]party.ID, 0, n)
	for id := range shares {
		IDs = append(IDs, id)
	}

	set := party.NewIDSlice(IDs)

	s := &Public{
		PartyIDs:  set,
		Threshold: threshold,
		Shares:    shares,
		GroupKey:  computeGroupKey(set, shares),
	}

	if s.Threshold+1 > s.PartyIDs.N() {
		return nil, errors.New("PublicShares: Threshold should be < N - 1")
	}

	return s, nil
}

// computeGroupKey computes the interpolation of the shares with regards to the partyIDs
func computeGroupKey(partyIDs party.IDSlice, shares map[party.ID]*ristretto.Element) *PublicKey {
	var tmp ristretto.Element

	groupKey := ristretto.NewIdentityElement()
	for _, id := range partyIDs {
		lagrange := id.Lagrange(partyIDs)
		tmp.ScalarMult(lagrange, shares[id])
		groupKey.Add(groupKey, &tmp)
	}
	return NewPublicKeyFromPoint(groupKey)
}

type sharesJSON struct {
	Threshold int                             `json:"t"`
	GroupKey  *PublicKey                      `json:"groupkey"`
	Shares    map[party.ID]*ristretto.Element `json:"shares"`
}

// MarshalJSON implements the json.Marshaler interface.
func (s *Public) MarshalJSON() ([]byte, error) {
	return json.Marshal(sharesJSON{
		Threshold: int(s.Threshold),
		Shares:    s.Shares,
		GroupKey:  s.GroupKey,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *Public) UnmarshalJSON(data []byte) error {
	var out sharesJSON

	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}

	newS, err := NewPublic(out.Shares, party.Size(out.Threshold))
	if err != nil {
		return err
	}
	computedGroupKey := computeGroupKey(newS.PartyIDs, out.Shares)
	if !computedGroupKey.Equal(out.GroupKey) {
		return errors.New("PublicShares: inconsistent group key")
	}

	*s = *newS

	return nil
}

func (s *Public) Equal(s2 *Public) bool {
	if len(s.Shares) != len(s2.Shares) {
		return false
	}

	if !s.PartyIDs.Equal(s2.PartyIDs) {
		return false
	}

	if s.Threshold != s2.Threshold {
		return false
	}

	if !s.GroupKey.Equal(s2.GroupKey) {
		return false
	}

	for _, id := range s.PartyIDs {
		p1 := s.Shares[id]
		p2 := s2.Shares[id]
		if p1.Equal(p2) != 1 {
			return false
		}
	}

	return true
}
