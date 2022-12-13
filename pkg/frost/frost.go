package frost

import (
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/coordinator"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/signer"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/state/hub"
	"github.com/taurusgroup/frost-ed25519/pkg/state/spoke"
)

// NewKeygenState returns a state.State which coordinates the multiple rounds.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewKeygenState(selfID party.ID, partyIDs party.IDSlice, threshold party.Size, timeout time.Duration) (*hub.State, *keygen.Output, error) {
	round, output, err := keygen.NewRound(selfID, partyIDs, threshold)
	if err != nil {
		return nil, nil, err
	}
	s, err := hub.NewBaseState(round, timeout)
	if err != nil {
		return nil, nil, err
	}
	go func() {}()
	return s, output, nil
}

func NewCoordinatorState(hubID party.ID, partyIDs party.IDSlice, shares *eddsa.Public, message []byte, timeout time.Duration) (*hub.State, *types.Output, error) {
	round, output, err := coordinator.NewRound(hubID, partyIDs, shares, message)
	if err != nil {
		return nil, nil, err
	}
	s, err := hub.NewBaseState(round, timeout)
	if err != nil {
		return nil, nil, err
	}

	return s, output, nil
}

// NewSignState returns a state.State which coordinates the multiple rounds.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewSignerState(hubID party.ID, partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, timeout time.Duration) (*spoke.State, error) {
	round, err := signer.NewRound(hubID, partyIDs, secret, shares)
	if err != nil {
		return nil, err
	}
	s, err := spoke.NewBaseState(round, timeout)
	if err != nil {
		return nil, err
	}

	return s, nil
}
