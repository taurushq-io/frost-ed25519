package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type (
	round0 struct {
		partySet *party.SetWithSelf

		// Threshold is the degree of the polynomial used for Shamir.
		// It is the number of tolerated party corruptions.
		Threshold party.Size

		// Secret is first set to the zero coefficient of the polynomial we send to the other parties.
		// Once all received shares are declared, they are summed here to produce the party's
		// final secret key.
		Secret edwards25519.Scalar

		// Polynomial used to sample shares
		Polynomial *polynomial.Polynomial

		// CommitmentsSum is the sum of all commitments, we use it to compute public key shares
		CommitmentsSum *polynomial.Exponent

		// Commitments contains all other parties commitment polynomials
		Commitments map[party.ID]*polynomial.Exponent

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
	Shares    *eddsa.Shares
	SecretKey *eddsa.PrivateKey
}

func NewRound(partySet *party.SetWithSelf, threshold party.Size) (rounds.Round, *Output, error) {
	N := partySet.N()

	if threshold == 0 {
		return nil, nil, errors.New("threshold must be at least 1, or a minimum of T+1=2 signers")
	}
	if threshold > N-1 {
		return nil, nil, errors.New("threshold must be at most N-1, or a maximum of T+1=N signers")
	}

	r := round0{
		partySet:    partySet,
		Threshold:   threshold,
		Commitments: make(map[party.ID]*polynomial.Exponent, N),
		Output:      &Output{},
	}

	return &r, r.Output, nil
}

func (round *round0) Reset() {
	round.Secret.Set(edwards25519.NewScalar())
	round.Polynomial.Reset()
	round.CommitmentsSum.Reset()
	for _, p := range round.Commitments {
		p.Reset()
	}
}

// ---
// Messages
// ---

func (round *round0) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}
}
