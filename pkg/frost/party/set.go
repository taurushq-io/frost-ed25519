package party

import (
	"errors"
	"sort"
)

type SetWithSelf struct {
	selfID ID
	*Set
}

type Set struct {
	set   map[ID]bool
	slice []ID
}

func NewSetWithSelf(selfID ID, partyIDs []ID) (*SetWithSelf, error) {
	set, err := NewSet(partyIDs)
	if err != nil {
		return nil, err
	}
	if selfID != 0 && !set.Contains(selfID) {
		return nil, errors.New("partyIDs should contain selfID")
	}
	return &SetWithSelf{
		selfID: selfID,
		Set:    set,
	}, nil
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

func (s *Set) Without(id ID) (*Set, error) {
	newSlice := make([]ID, 0, len(s.set)-1)
	for _, otherID := range newSlice {
		if otherID != id {
			newSlice = append(newSlice, otherID)
		}
	}
	return NewSet(newSlice)
}

func (s *SetWithSelf) Without(id ID) (*SetWithSelf, error) {
	if id == s.selfID {
		return nil, errors.New("cannot remove self")
	}
	newSlice := make([]ID, 0, len(s.set)-1)
	for _, otherID := range newSlice {
		if otherID != id {
			newSlice = append(newSlice, otherID)
		}
	}
	return NewSetWithSelf(s.selfID, newSlice)
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

func (s *SetWithSelf) Self() ID {
	return s.selfID
}
