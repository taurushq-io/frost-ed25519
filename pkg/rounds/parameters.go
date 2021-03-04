package rounds

import (
	"errors"
	"sort"
)

type Parameters struct {
	id          uint32
	allPartyIDs []uint32
	partyIDsSet map[uint32]bool
}

func NewParameters(selfPartyID uint32, allPartyIDs []uint32) (*Parameters, error) {
	if selfPartyID == 0 {
		return nil, errors.New("selfPartyID cannot be 0")
	}

	sortedAllPartyIDs := make([]uint32, 0, len(allPartyIDs))
	otherPartyIDs := make(map[uint32]bool, len(allPartyIDs))

	foundSelfIDInAll := false
	for _, id := range allPartyIDs {
		if id == 0 {
			return nil, errors.New("IDs in allPartyIDs cannot be 0")
		}

		if _, alreadyAdded := otherPartyIDs[id]; !alreadyAdded {
			sortedAllPartyIDs = append(sortedAllPartyIDs, id)
		}

		if id == selfPartyID {
			foundSelfIDInAll = true
		} else {
			otherPartyIDs[id] = true
		}
	}
	if !foundSelfIDInAll {
		return nil, errors.New("selfPartyID must be included in allPartyIDs")
	}

	sort.Slice(sortedAllPartyIDs, func(i, j int) bool { return sortedAllPartyIDs[i] < sortedAllPartyIDs[j] })

	if len(sortedAllPartyIDs) != len(otherPartyIDs)+1 {
		return nil, errors.New("something went wrong with filtering")
	}

	p := &Parameters{
		id:          selfPartyID,
		allPartyIDs: sortedAllPartyIDs,
		partyIDsSet: otherPartyIDs,
	}
	return p, nil
}

// SelfID is the ID of the current party.
func (p *Parameters) SelfID() uint32 {
	return p.id
}

// AllPartyIDs is a sorted list of uint32 which represent all parties (including this one)
// that are participating in the Round
func (p *Parameters) AllPartyIDs() []uint32 {
	return p.allPartyIDs
}

func (p *Parameters) IsParticipating(otherPartyID uint32) bool {
	return p.partyIDsSet[otherPartyID]
}

// N returns the number of parties participating.
func (p *Parameters) N() int {
	return len(p.allPartyIDs)
}

// OtherPartyIDs is a set of IDs from all other parties. It is not ordered, and is mostly used to
// iterate over the list of IDs.
func (p *Parameters) OtherPartyIDsSet() map[uint32]bool {
	return p.partyIDsSet
}

func (p *Parameters) Copy() *Parameters {
	partyIDsSet := make(map[uint32]bool, len(p.allPartyIDs))
	for id := range p.partyIDsSet {
		partyIDsSet[id] = p.partyIDsSet[id]
	}
	q := &Parameters{
		id:          p.id,
		allPartyIDs: append([]uint32{}, p.allPartyIDs...),
		partyIDsSet: partyIDsSet,
	}
	return q
}
