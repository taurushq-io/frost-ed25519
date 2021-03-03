package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type (
	round0 struct {
		*rounds.Parameters

		// Threshold is the degree of the polynomial used for Shamir.
		// It is the number of tolerated party corruptions.
		Threshold uint32

		// Secret is first set to the zero coefficient of the polynomial we send to the other parties.
		// Once all received shares are declared, they are summed here to produce the party's
		// final secret key.
		Secret edwards25519.Scalar

		// Polynomial used to sample shares
		Polynomial *polynomial.Polynomial

		// CommitmentsSum is the sum of all commitments, we use it to compute public key shares
		CommitmentsSum *polynomial.Exponent

		// Commitments contains all other parties commitment polynomials
		Commitments map[uint32]*polynomial.Exponent

		Output *Output
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

type Output struct {
	*state.BaseOutput
	Shares    *eddsa.Shares
	SecretKey *eddsa.PrivateKey
}

func NewRound(params *rounds.Parameters, threshold uint32) (rounds.Round, *Output, error) {
	N := params.N()

	if int(threshold) == 0 {
		return nil, nil, errors.New("threshold must be at least 1, or a minimum of T+1=2 signers")
	}
	if int(threshold) > N-1 {
		return nil, nil, errors.New("threshold must be at most N-1, or a maximum of T+1=N signers")
	}

	r := round0{
		Parameters:  params,
		Threshold:   threshold,
		Commitments: make(map[uint32]*polynomial.Exponent, N),
		Output:      &Output{BaseOutput: state.NewBaseOutput()},
	}

	return &r, r.Output, nil
}

func (round *round0) Reset() {
	round.Secret.Set(edwards25519.NewScalar())
	if round.Polynomial != nil {
		round.Polynomial.Reset()
	}
	for _, p := range round.Commitments {
		if p != nil {
			p.Reset()
		}
	}
}

// ---
// Messages
// ---

var acceptedMessageTypes = []messages.MessageType{messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}

func (round *round0) AcceptedMessageTypes() []messages.MessageType {
	return acceptedMessageTypes
}
