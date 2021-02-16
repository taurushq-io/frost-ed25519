package keygen

import (
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/zk"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round0) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()

	// Sample a_i,0 which is the constant factor of the polynomial
	secret := scalar.NewScalarRandom()

	// Sample the remaining coefficients, and obtain a polynomial
	// of degree t.
	round.Polynomial = polynomial.NewPolynomial(round.Threshold, secret)

	// Generate all commitments [a_i,j] B for j = 0, 1, ..., t
	round.CommitmentsSum = polynomial.NewPolynomialExponent(round.Polynomial)
}

func (round *round0) GenerateMessages() []*messages.Message {
	if !round.CanGenerateMessages() {
		return nil
	}
	defer round.NextStep()

	secret := round.Polynomial.Evaluate(0)

	// Generate proof of knowledge of a_i,0 = f(0)
	proof, _ := zk.NewSchnorrProof(secret, round.ID(), "")

	msg := messages.NewKeyGen1(round.ID(), proof, round.CommitmentsSum)

	return []*messages.Message{msg}
}

func (round *round0) NextRound() rounds.Round {
	if round.PrepareNextRound() {
		return &round1{round}
	}

	return round
}
