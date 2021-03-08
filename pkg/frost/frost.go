package frost

import (
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

// NewKeygenState returns a state.State which coordinates the multiple rounds.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewKeygenState(partyID party.ID, partySet *party.Set, threshold party.Size, timeout time.Duration) (*state.State, *keygen.Output, error) {
	round, output, err := keygen.NewRound(partyID, partySet, threshold)
	if err != nil {
		return nil, nil, err
	}
	s, err := state.NewBaseState(round, timeout)
	if err != nil {
		return nil, nil, err
	}

	go func() {}()
	return s, output, nil
}

// NewSignState returns a state.State which coordinates the multiple rounds.
// The second parameter is the output of the protocol and will be filled with the output once the protocol has finished executing.
// It is safe to use the output when State.WaitForError() returns nil.
func NewSignState(partySet *party.Set, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte, timeout time.Duration) (*state.State, *sign.Output, error) {
	round, output, err := sign.NewRound(partySet, secret, shares, message)
	if err != nil {
		return nil, nil, err
	}
	s, _ := state.NewBaseState(round, timeout)

	return s, output, nil
}
