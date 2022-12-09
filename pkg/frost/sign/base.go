package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/types"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func NewRound(version types.ProtocolVersion, partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (state.Round, *Output, error) {
	if !partyIDs.Contains(secret.ID) {
		return nil, nil, errors.New("base.NewRound: owner of SecretShare is not contained in partyIDs")
	}
	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, errors.New("base.NewRound: not all parties of partyIDs are contained in shares")
	}

	baseRound, err := state.NewBaseRound(secret.ID, partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}

	round := &types.round0{
		BaseRound: baseRound,
		Version:   version,
		Message:   message,
		Parties:   make(map[party.ID]*types.Signer, partyIDs.N()),
		GroupKey:  *shares.GroupKey,
		Output:    &Output{},
	}

	// Setup parties
	for _, id := range partyIDs {
		var s types.Signer
		if id == 0 {
			return nil, nil, errors.New("base.NewRound: id 0 is not valid")
		}
		originalShare := shares.Shares[id]
		lagrange, err := id.Lagrange(partyIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("base.NewRound: %w", err)
		}
		s.Public.ScalarMult(lagrange, originalShare)
		round.Parties[id] = &s
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := round.SelfID().Lagrange(partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}
	round.SecretKeyShare.Multiply(lagrange, &secret.Secret)

	return round, round.Output, nil
}
