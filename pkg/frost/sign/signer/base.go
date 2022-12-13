package signer

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/state/spoke"
)

func NewRound(hubID party.ID, partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public) (spoke.SpokeRound, error) {
	if !partyIDs.Contains(secret.ID) {
		return nil, errors.New("base.NewRound: owner of SecretShare is not contained in partyIDs")
	}
	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, errors.New("base.NewRound: not all parties of partyIDs are contained in shares")
	}

	baseRound, err := spoke.NewBaseRound(secret.ID, hubID, partyIDs)
	if err != nil {
		return nil, fmt.Errorf("base.NewRound: %w", err)
	}

	round := &Round0Signer{
		BaseRound: baseRound,
		FrostRound: &types.FrostRound{
			Parties:  make(map[party.ID]*types.Signer, partyIDs.N()),
			GroupKey: *shares.GroupKey,
		},
	}

	// Setup parties
	for _, id := range partyIDs {
		round.Parties[id] = &types.Signer{}
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := round.SelfID().Lagrange(partyIDs)
	if err != nil {
		return nil, fmt.Errorf("base.NewRound: %w", err)
	}
	round.SecretKeyShare.Multiply(lagrange, &secret.Secret)

	return round, nil
}
