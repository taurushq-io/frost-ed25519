package eddsa

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

// Shares holds the public keys generated during a key generation protocol.
// It also stores the associated party set, the threshold used and the full group key.
type Shares struct {
	// PartySet is a party.Set but does not specify a particular ID.
	// This is because the Shares struct is independent of the owner of a particular share.
	PartySet  *party.Set
	threshold party.Size
	shares    map[party.ID]*edwards25519.Point
	groupKey  *edwards25519.Point
}

// NewShares creates a Shares structure given a map of edwards25519.Point, the threshold used, and an optional group key.
// If groupKey is nil, then it is recomputed. Otherwise it is considered correct and simply stored.
func NewShares(shares map[party.ID]*edwards25519.Point, threshold party.Size, groupKey *edwards25519.Point) *Shares {
	n := len(shares)
	IDs := make([]party.ID, 0, n)
	for id := range shares {
		IDs = append(IDs, id)
	}

	set, err := party.NewSet(IDs)
	if err != nil {
		panic(err)
	}

	s := &Shares{
		PartySet:  set,
		threshold: threshold,
		shares:    shares,
		groupKey:  groupKey,
	}

	if groupKey == nil {
		s.computeGroupKey()
	}

	return s
}

func (s *Shares) computeGroupKey() {
	var tmp edwards25519.Point
	s.groupKey = edwards25519.NewIdentityPoint()

	for id := range s.PartySet.Range() {
		lagrange, _ := s.PartySet.Lagrange(id)
		tmp.ScalarMult(lagrange, s.shares[id])
		s.groupKey.Add(s.groupKey, &tmp)
	}
}

// GroupKey returns the group key of the group by interpolating all the given points.
func (s *Shares) GroupKey() *PublicKey {
	return NewPublicKeyFromPoint(s.groupKey)
}

// Share returns the PublicKey for the party at index.
func (s *Shares) Share(index party.ID) (*PublicKey, error) {
	p, ok := s.shares[index]
	if !ok {
		return nil, fmt.Errorf("shares does not contain partyID %d", index)
	}
	return NewPublicKeyFromPoint(p), nil
}

// ShareNormalized returns the party index's public key share, but multiplied by the appropriate Lagrange factor of
// the group determined by partyIDs.
// If ShareNormalized is called for every party in partyIDs, then the resulting PublicKey s represent
// an additive sharing of the group key.
func (s *Shares) ShareNormalized(partyID party.ID, partySet *party.Set) (*PublicKey, error) {
	if partySet.N() < s.threshold+1 {
		return nil, errors.New("partyIDs does not contain a threshold number of PartySet")
	}
	if !partySet.IsSubsetOf(s.PartySet) {
		return nil, errors.New("given partyIDs is not a subset of the original partyIDs")
	}

	pk, err := s.Share(partyID)

	if err != nil {
		return nil, err
	}
	lagrange, err := partySet.Lagrange(partyID)
	if err != nil {
		return nil, err
	}
	pk.pk.ScalarMult(lagrange, &pk.pk)
	return pk, nil
}

// Threshold returns the integer which defines the maximum number of parties that may be corrupted while
// keeping the scheme secure.
func (s *Shares) Threshold() party.Size {
	return s.threshold
}

// MarshalBinary implements the BinaryMarshaler interface.
func (s *Shares) MarshalBinary() ([]byte, error) {
	N := s.PartySet.N()
	size := 2*party.ByteSize + 32 + N*(party.ByteSize+32)
	out := make([]byte, 0, size)
	out = append(out, N.Bytes()...)
	out = append(out, s.threshold.Bytes()...)
	out = append(out, s.groupKey.Bytes()...)

	for _, id := range s.PartySet.Sorted() {
		out = append(out, id.Bytes()...)
		out = append(out, s.shares[id].Bytes()...)
	}
	return out, nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface.
func (s *Shares) UnmarshalBinary(data []byte) error {
	var err error
	n := party.FromBytes(data)
	data = data[party.ByteSize:]

	if len(data) != int(party.ByteSize+32+n*(party.ByteSize+32)) {
		return errors.New("encoded n is inconsistent with data length")
	}

	t := party.FromBytes(data)
	data = data[party.ByteSize:]
	if t+1 > n {
		return errors.New("t should be < n - 1")
	}

	var groupKey edwards25519.Point
	_, err = groupKey.SetBytes(data[:32])
	if err != nil {
		return err
	}
	data = data[32:]

	partyIDs := make([]party.ID, n)
	sharesSlice := make([]edwards25519.Point, n)
	shares := make(map[party.ID]*edwards25519.Point, n)

	for i := party.Size(0); i < n; i++ {
		partyIDs[i] = party.FromBytes(data)
		data = data[party.ByteSize:]
		id := partyIDs[i]
		shares[id], err = sharesSlice[i].SetBytes(data[:32])
		data = data[32:]
		if err != nil {
			return err
		}
	}
	s.threshold = t
	s.PartySet, err = party.NewSet(partyIDs)
	if err != nil {
		return err
	}
	s.shares = shares

	s.computeGroupKey()
	if groupKey.Equal(s.groupKey) != 1 {
		return errors.New("stored GroupKey does not correspond")
	}

	return nil
}

type sharesJSON struct {
	Threshold int               `json:"t"`
	GroupKey  string            `json:"groupkey"`
	Shares    map[string]string `json:"shares"`
}

func (s *Shares) MarshalJSON() ([]byte, error) {
	sharesText := make(map[string]string, len(s.shares))
	for _, id := range s.PartySet.Sorted() {
		idText := strconv.FormatUint(uint64(id), 10)
		shareHex := hex.EncodeToString(s.shares[id].Bytes())
		sharesText[idText] = shareHex
	}

	groupKeyHex := hex.EncodeToString(s.groupKey.Bytes())
	sharesJson := sharesJSON{
		Threshold: int(s.threshold),
		Shares:    sharesText,
		GroupKey:  groupKeyHex,
	}
	return json.Marshal(sharesJson)
}

// TODO verify group key
func (s *Shares) UnmarshalJSON(data []byte) error {
	var sharesJson sharesJSON
	err := json.Unmarshal(data, &sharesJson)
	if err != nil {
		return err
	}
	n := party.Size(len(sharesJson.Shares))
	t := party.Size(sharesJson.Threshold)
	if t+1 > n {
		return errors.New("t should be < n - 1")
	}

	partyIDs := make([]party.ID, 0, n)
	sharesSlice := make([]edwards25519.Point, n)
	shares := make(map[party.ID]*edwards25519.Point, n)
	for idText, pointHex := range sharesJson.Shares {
		id, err := party.IDFromString(idText)
		if err != nil {
			return err
		}
		pointBytes, err := hex.DecodeString(pointHex)
		if err != nil {
			return err
		}

		i := len(partyIDs)
		partyIDs = append(partyIDs, id)
		shares[id], err = sharesSlice[i].SetBytes(pointBytes)
		if err != nil {
			return err
		}
	}
	s.threshold = t
	s.PartySet, err = party.NewSet(partyIDs)
	if err != nil {
		return err
	}
	s.shares = shares

	var groupKey edwards25519.Point
	s.computeGroupKey()
	groupKeyBytes, err := hex.DecodeString(sharesJson.GroupKey)
	_, err = groupKey.SetBytes(groupKeyBytes)
	if err != nil {
		return err
	}

	if groupKey.Equal(s.groupKey) != 1 {
		return errors.New("stored GroupKey does not correspond")
	}

	return nil
}

func (s *Shares) Equal(s2 *Shares) bool {
	if len(s.shares) != len(s2.shares) {
		return false
	}

	if !s.PartySet.Equal(s2.PartySet) {
		return false
	}

	if s.threshold != s2.threshold {
		return false
	}

	if s.groupKey.Equal(s2.groupKey) != 1 {
		return false
	}

	for _, id := range s.PartySet.Sorted() {
		p1 := s.shares[id]
		p2 := s2.shares[id]
		if p1.Equal(p2) != 1 {
			return false
		}
	}

	return true
}
