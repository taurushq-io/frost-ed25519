package eddsa

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

// Shares holds the public keys generated during a key generation protocol.
// It should
type Shares struct {
	threshold   uint32
	allPartyIDs []uint32
	partyIDsSet map[uint32]bool
	shares      map[uint32]*edwards25519.Point
	groupKey    *edwards25519.Point
}

func NewShares(shares map[uint32]*edwards25519.Point, threshold uint32, groupKey *edwards25519.Point) *Shares {
	n := len(shares)
	s := &Shares{
		threshold:   threshold,
		allPartyIDs: make([]uint32, 0, n),
		partyIDsSet: make(map[uint32]bool, n),
		shares:      shares,
		groupKey:    groupKey,
	}
	for id := range shares {
		s.allPartyIDs = append(s.allPartyIDs, id)
		s.partyIDsSet[id] = true
	}

	sortSliceUInt32(s.allPartyIDs)

	if groupKey == nil {
		s.computeGroupKey()
	}

	return s
}

func (s *Shares) computeGroupKey() {
	var tmp edwards25519.Point
	s.groupKey = edwards25519.NewIdentityPoint()
	partyIDs := s.allPartyIDs[:s.threshold+1]

	for _, id := range partyIDs {
		lagrange, _ := s.Lagrange(id, partyIDs)
		tmp.ScalarMult(lagrange, s.shares[id])
		s.groupKey.Add(s.groupKey, &tmp)
	}
}

func (s *Shares) GroupKey() *PublicKey {
	return NewPublicKeyFromPoint(s.groupKey)
}

func (s *Shares) Share(index uint32) (*PublicKey, error) {
	p, ok := s.shares[index]
	if !ok {
		return nil, fmt.Errorf("shares does not contain partyID %d", index)
	}
	return NewPublicKeyFromPoint(p), nil
}

func (s *Shares) ShareNormalized(index uint32, partyIDs []uint32) (*PublicKey, error) {
	if len(partyIDs) < int(s.threshold)+1 {
		return nil, errors.New("partyIDs does not contain a threshold number of parties")
	}
	if !s.partySliceIsSubset(partyIDs) {
		return nil, errors.New("given partyIDs is not a subset of the original partyIDs")
	}

	pk, err := s.Share(index)

	if err != nil {
		return nil, err
	}
	lagrange, err := s.Lagrange(index, partyIDs)
	if err != nil {
		return nil, err
	}
	pk.pk.ScalarMult(lagrange, &pk.pk)
	return pk, nil
}

func (s *Shares) PartyIDs() []uint32 {
	return append([]uint32(nil), s.allPartyIDs...)
}

func (s *Shares) Threshold() uint32 {
	return s.threshold
}

func (s *Shares) partySliceIsSubset(partyIDs []uint32) bool {
	for _, id := range partyIDs {
		if !s.partyIDsSet[id] {
			return false
		}
	}
	return true
}

func (s *Shares) MarshalBinary() ([]byte, error) {
	offset := 0
	size := 4 + 4 + 32 + len(s.allPartyIDs)*(4+32)
	out := make([]byte, size)
	binary.BigEndian.PutUint32(out[offset:], uint32(len(s.allPartyIDs)))
	offset += 4
	binary.BigEndian.PutUint32(out[offset:], s.threshold)
	offset += 4
	copy(out[offset:], s.groupKey.Bytes())
	offset += 32

	for _, id := range s.allPartyIDs {
		binary.BigEndian.PutUint32(out[offset:], id)
		offset += 4
		copy(out[offset:], s.shares[id].Bytes())
		offset += 32
	}
	return out, nil
}

func (s *Shares) UnmarshalBinary(data []byte) error {
	var err error
	offset := 0
	n := binary.BigEndian.Uint32(data[offset:])
	if len(data) != int(8+32+n*(4+32)) {
		return errors.New("encoded n is inconsistent with data length")
	}

	offset += 4
	t := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if t+1 > n {
		return errors.New("t should be < n - 1")
	}

	var groupKey edwards25519.Point
	_, err = groupKey.SetBytes(data[offset : offset+32])
	if err != nil {
		return err
	}
	offset += 32

	partyIDs := make([]uint32, n)
	sharesSlice := make([]edwards25519.Point, n)
	shares := make(map[uint32]*edwards25519.Point, n)
	partyIDsSet := make(map[uint32]bool, n)

	for i := uint32(0); i < n; i++ {
		partyIDs[i] = binary.BigEndian.Uint32(data[offset:])
		offset += 4
		id := partyIDs[i]
		shares[id], err = sharesSlice[i].SetBytes(data[offset : offset+32])
		if err != nil {
			return err
		}
		offset += 32

		partyIDsSet[id] = true
	}
	sortSliceUInt32(partyIDs)
	s.threshold = t
	s.allPartyIDs = partyIDs
	s.partyIDsSet = partyIDsSet
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
	for _, id := range s.allPartyIDs {
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
	n := uint32(len(sharesJson.Shares))
	t := uint32(sharesJson.Threshold)
	if t+1 > n {
		return errors.New("t should be < n - 1")
	}

	partyIDs := make([]uint32, 0, n)
	sharesSlice := make([]edwards25519.Point, n)
	shares := make(map[uint32]*edwards25519.Point, n)
	partyIDsSet := make(map[uint32]bool, n)

	for idText, pointHex := range sharesJson.Shares {
		id64, err := strconv.ParseUint(idText, 10, 32)
		if err != nil {
			return err
		}
		id := uint32(id64)
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

		partyIDsSet[id] = true
	}
	sortSliceUInt32(partyIDs)
	s.threshold = t
	s.allPartyIDs = partyIDs
	s.partyIDsSet = partyIDsSet
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

	if len(s.allPartyIDs) != len(s2.allPartyIDs) {
		return false
	}

	if len(s.partyIDsSet) != len(s2.partyIDsSet) {
		return false
	}

	if s.threshold != s2.threshold {
		return false
	}

	if s.groupKey.Equal(s2.groupKey) != 1 {
		return false
	}

	for i := range s.allPartyIDs {
		id1 := s.allPartyIDs[i]
		id2 := s2.allPartyIDs[i]
		if id1 != id2 {
			return false
		}
		id := id1

		p1 := s.shares[id]
		p2 := s2.shares[id]
		if p1.Equal(p2) != 1 {
			return false
		}

		if !s2.partyIDsSet[id] {
			return false
		}
	}

	return true
}

func sortSliceUInt32(a []uint32) {
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
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
func (s *Shares) Lagrange(idx uint32, partyIDs []uint32) (*edwards25519.Scalar, error) {
	if !s.partySliceIsSubset(partyIDs) {
		return nil, errors.New("given partyIDs is not a subset of the original partyIDs")
	}

	var xM edwards25519.Scalar

	denum := scalar.NewScalarUInt32(uint32(1))
	num := scalar.NewScalarUInt32(uint32(1))

	xJ := scalar.NewScalarUInt32(idx)

	for _, id := range partyIDs {
		if id == idx {
			continue
		}

		scalar.SetScalarUInt32(&xM, id)

		// num = x_0 * ... * x_k
		num.Multiply(num, &xM) // num * xM

		// denum = (x_0 - x_j) ... (x_k - x_j)
		xM.Subtract(&xM, xJ)       // = xM - xJ
		denum.Multiply(denum, &xM) // denum * (xm - xj)
	}

	// This should not happen since xM!=xJ
	if denum.Equal(edwards25519.NewScalar()) == 1 {
		return nil, errors.New("partyIDs contained idx")
	}

	denum.Invert(denum)
	num.Multiply(num, denum)
	return num, nil
}
