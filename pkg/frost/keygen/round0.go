package keygen

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/common"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/zk"
)

func (round *base) ProcessMessages() error {
	round.Lock()
	defer round.Unlock()

	if round.messagesProcessed {
		return nil
	}

	round.messagesProcessed = true

	return nil
}

func (round *base) ProcessRound() error {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed {
		return nil
	}

	// Sample a_i,0 which is the constant factor of the polynomial
	secret := common.NewScalarRandom()

	// Sample the remaining coefficients, and obtain a polynomial
	// of degree t.
	round.Polynomial = polynomial.NewPolynomial(round.Threshold, secret)

	// Generate all commitments [a_i,j] B for j = 0, 1, ..., t
	round.CommitmentsSum = polynomial.NewPolynomialExponent(round.Polynomial)

	round.roundProcessed = true

	return nil
}

func (round *base) GenerateMessages() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if !(round.roundProcessed && round.messagesProcessed) {
		return nil, frost.ErrRoundNotProcessed
	}

	secret := round.Polynomial.Evaluate(0)

	// Generate proof of knowledge of a_i,0 = f(0)
	proof, _ := zk.NewSchnorrProof(secret, round.PartySelf, "")

	msg := messages.NewKeyGen1(round.PartySelf, proof, round.CommitmentsSum)

	return []*messages.Message{msg}, nil
}

func (round *base) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed && round.messagesProcessed {
		round.roundProcessed = false
		round.messagesProcessed = false
		return &round1{round}
	}

	return round
}
