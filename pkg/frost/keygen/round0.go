package keygen

import (
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/zk"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func (round *round0) ProcessMessage(msg *messages.Message) *state.Error {
	return nil
}

func (round *round0) GenerateMessages() ([]*messages.Message, *state.Error) {
	// Sample a_i,0 which is the constant factor of the polynomial
	scalar.SetScalarRandom(&round.Secret)

	// Sample the remaining coefficients, and obtain a polynomial
	// of degree t.
	round.Polynomial = polynomial.NewPolynomial(round.Threshold, &round.Secret)

	// Generate all commitments [a_i,j] B for j = 0, 1, ..., t
	// CommitmentsSum holds the sum of all commitments, so we initialize it to our commitment
	round.CommitmentsSum = polynomial.NewPolynomialExponent(round.Polynomial)

	// TODO we can use custom contexts to prevent replay attacks
	ctx := make([]byte, 32)
	public := round.CommitmentsSum.Constant()
	// Generate proof of knowledge of a_i,0 = f(0)
	proof := zk.NewSchnorrProof(round.SelfID(), public, ctx, &round.Secret)

	// We use the variable Secret to hold the sum of all shares received.
	// Therefore, we can set it to the share we would send to our selves.
	// Bonus, we overwrite the original secret which is no longer needed.
	round.Secret.Set(round.Polynomial.Evaluate(round.SelfID().Scalar()))

	msg := messages.NewKeyGen1(round.SelfID(), proof, round.CommitmentsSum)
	return []*messages.Message{msg}, nil
}

func (round *round0) NextRound() state.Round {
	return &round1{round}
}
