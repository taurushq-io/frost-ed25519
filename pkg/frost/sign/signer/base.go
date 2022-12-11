package signer

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
	"github.com/taurusgroup/frost-ed25519/pkg/state/spoke"
)

func NewSignerRound(version types.ProtocolVersion, hubID party.ID, partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (state.Round, *types.Output, error) {
	if !partyIDs.Contains(secret.ID) {
		return nil, nil, errors.New("base.NewRound: owner of SecretShare is not contained in partyIDs")
	}
	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, errors.New("base.NewRound: not all parties of partyIDs are contained in shares")
	}

	baseSpokeRound, err := spoke.NewBaseSpokeRound(secret.ID, hubID, partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}

	round := &Round0Signer{
		BaseSpokeRound: baseSpokeRound,
		FrostRound: &types.FrostRound{
			Version:  version,
			Message:  message,
			Parties:  make(map[party.ID]*types.Signer, partyIDs.N()),
			GroupKey: *shares.GroupKey,
			Output:   &types.Output{},
		},
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
