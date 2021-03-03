package keygen

import (
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/zk"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round0) ProcessMessage(msg *messages.Message) *rounds.Error {
	return nil
}

func (round *round0) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	// Sample a_i,0 which is the constant factor of the polynomial
	secret := scalar.NewScalarRandom()

	// Sample the remaining coefficients, and obtain a polynomial
	// of degree t.
	round.Polynomial = polynomial.NewPolynomial(round.Threshold, secret)

	// We use the variable Secret to hold the sum of all shares received.
	// Therefore, we can set it to the share we would send to our selves.
	round.Secret.Set(round.Polynomial.Evaluate(round.SelfID()))

	// Generate all commitments [a_i,j] B for j = 0, 1, ..., t
	commitments := polynomial.NewPolynomialExponent(round.Polynomial)
	ctx := make([]byte, 32)
	public := commitments.Constant()
	// Generate proof of knowledge of a_i,0 = f(0)
	proof := zk.NewSchnorrProof(round.SelfID(), public, ctx, secret)

	// CommitmentsSum holds the sum of all commitments, so we initialize it to our commitment
	round.CommitmentsSum = commitments

	msg := messages.NewKeyGen1(round.SelfID(), proof, commitments)
	return []*messages.Message{msg}, nil
}

func (round *round0) NextRound() rounds.Round {
	return &round1{round}
}
