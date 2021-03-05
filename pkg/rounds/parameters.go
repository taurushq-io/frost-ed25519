package rounds

//type Parameters struct {
//	id party.ID
//	*party.SetWithoutSelf
//}
//
//func NewParameters(selfPartyID party.ID, allPartyIDs []party.ID) (*Parameters, error) {
//	if selfPartyID == 0 {
//		return nil, errors.New("selfPartyID cannot be 0")
//	}
//
//	set, err := party.NewSetWithSelf(selfPartyID, allPartyIDs)
//	if err != nil {
//		return nil, err
//	}
//
//	if !set.Contains(selfPartyID) {
//		return nil, errors.New("selfPartyID must be included in allPartyIDs")
//	}
//	p := &Parameters{
//		id:  selfPartyID,
//		SetWithoutSelf: set,
//	}
//
//	return p, nil
//}

//// SelfID is the ID of the current party.
//func (p *Parameters) SelfID() party.ID {
//	return p.id
//}
//
//// AllPartyIDs is a sorted list of uint32 which represent all parties (including this one)
//// that are participating in the Round
//func (p *Parameters) AllPartyIDs() []party.ID {
//	return p.allPartyIDs
//}
//
//func (p *Parameters) IsParticipating(otherPartyID party.ID) bool {
//	return p.partyIDsSet[otherPartyID]
//}
//
//// N returns the number of parties participating.
//func (p *Parameters) N() party.Size {
//	return party.Size(len(p.allPartyIDs))
//}
//
//// OtherPartyIDs is a set of IDs from all other parties. It is not ordered, and is mostly used to
//// iterate over the list of IDs.
//func (p *Parameters) OtherPartyIDsSet() map[party.ID]bool {
//	return p.partyIDsSet
//}
//
//func (p *Parameters) Copy() *Parameters {
//	partyIDsSet := make(map[party.ID]bool, len(p.allPartyIDs))
//	for id := range p.partyIDsSet {
//		partyIDsSet[id] = p.partyIDsSet[id]
//	}
//	q := &Parameters{
//		id:          p.id,
//		allPartyIDs: append([]party.ID{}, p.allPartyIDs...),
//		partyIDsSet: partyIDsSet,
//	}
//	return q
//}
