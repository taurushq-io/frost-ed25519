package frost

import (
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func NewKeygenState(params *rounds.Parameters, threshold uint32, timeout time.Duration) (*state.State, *keygen.Output, error) {
	p := params.Copy()
	round, output, err := keygen.NewRound(p, threshold)
	if err != nil {
		return nil, nil, err
	}
	s := state.NewBaseState(p, round, timeout)

	return s, output, nil
}

func NewSignState(params *rounds.Parameters, secret *eddsa.PrivateKey, shares *eddsa.Shares, message []byte, timeout time.Duration) (*state.State, *sign.Output, error) {
	p := params.Copy()
	round, output, err := sign.NewRound(p, secret, shares, message)
	if err != nil {
		return nil, nil, err
	}
	s := state.NewBaseState(p, round, timeout)

	return s, output, nil
}
