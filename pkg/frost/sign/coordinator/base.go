package coordinator

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
	"github.com/taurusgroup/frost-ed25519/pkg/state/hub"
)

func NewCoordinatorRound(hubID party.ID, partyIDs party.IDSlice, shares *eddsa.Public, message []byte) (state.Round, *types.Output, error) {
	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, errors.New("base.NewRound: not all parties of partyIDs are contained in shares")
	}

	baseHubRound, err := hub.NewBaseHubRound(hubID, partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}

	round := &Round0Coordinator{
		BaseHubRound: baseHubRound,
		FrostRound: &types.FrostRound{
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

	return round, round.Output, nil
}
