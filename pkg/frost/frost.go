package frost

import (
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func NewKeygenState(partySet *party.SetWithSelf, threshold party.Size, timeout time.Duration) (*state.State, *keygen.Output, error) {
	round, output, err := keygen.NewRound(partySet, threshold)
	if err != nil {
		return nil, nil, err
	}
	s, err := state.NewBaseState(partySet, round, timeout)
	if err != nil {
		return nil, nil, err
	}

	return s, output, nil
}

func NewSignState(partySet *party.SetWithSelf, secret *eddsa.PrivateKey, shares *eddsa.Shares, message []byte, timeout time.Duration) (*state.State, *sign.Output, error) {
	round, output, err := sign.NewRound(partySet, secret, shares, message)
	if err != nil {
		return nil, nil, err
	}
	s, _ := state.NewBaseState(partySet, round, timeout)

	return s, output, nil
}
