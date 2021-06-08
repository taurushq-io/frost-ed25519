package party

import (
	"sort"
)

// IDSlice is an alias for []ID
type IDSlice []ID

// NewIDSlice returns an IDSlice which is the partyIDs sorted
func NewIDSlice(partyIDs []ID) IDSlice {
	ids := IDSlice(partyIDs).Copy()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Contains returns true if id is included in the slice.
func (ids IDSlice) Contains(id ID) bool {
	n := len(ids)
	i := sort.Search(n, func(i int) bool { return ids[i] >= id })
	if i < n && ids[i] == id {
		return true
	}
	return false
}

// N returns the number of ID s in the slice
func (ids IDSlice) N() Size {
	return Size(len(ids))
}

// IsSubsetOf is all elements in ids are in o
func (ids IDSlice) IsSubsetOf(o IDSlice) bool {
	for _, id := range ids {
		if !o.Contains(id) {
			return false
		}
	}
	return true
}

// Equal returns true if ids == o
func (ids IDSlice) Equal(o IDSlice) bool {
	if len(ids) != len(o) {
		return false
	}
	for idx, id := range ids {
		if o[idx] != id {
			return false
		}
	}
	return true
}

// Copy returns a deep copy of ids
func (ids IDSlice) Copy() IDSlice {
	n := len(ids)
	newIds := make([]ID, n)
	copy(newIds, ids)
	return newIds
}
