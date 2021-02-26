package keygen

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round1) ProcessMessages() {
	if !round.CanProcessMessages() {
		return
	}
	defer round.NextStep()

	msgs := round.Messages()
	ctx := make([]byte, 32)

	for _, msg := range msgs {
		if !msg.KeyGen1.Proof.Verify(msg.From, msg.KeyGen1.Commitments.Evaluate(0), ctx) {
			round.Abort(msg.From, errors.New("ZK Schnorr failed"))
			return
		}
	}

	for id, msg := range msgs {
		// Add the commitments to our own, so that we can interpolate the final polynomial
		err := round.CommitmentsSum.Add(msg.KeyGen1.Commitments)
		if err != nil {
			round.Abort(id, err)
			return
		}

		round.CommitmentsOthers[id] = msg.KeyGen1.Commitments
	}
}

func (round *round1) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()

	// We use the variable Secret to hold the sum of all shares received.
	// Therefore, we can set it to the share we would send to our selves.
	round.Secret.Set(round.Polynomial.Evaluate(round.ID()))
}

func (round *round1) GenerateMessages() []*messages.Message {
	if !round.CanGenerateMessages() {
		return nil
	}
	defer round.NextStep()

	msgsOut := make([]*messages.Message, 0, round.N()-1)
	for id := range round.OtherPartyIDs {
		msgsOut = append(msgsOut, messages.NewKeyGen2(round.ID(), id, round.Polynomial.Evaluate(id)))
	}

	// Now that we have received the commitment from every one,
	// we no longer require the original polynomial, so we reset it
	round.Polynomial.Reset()

	return msgsOut
}

func (round *round1) NextRound() rounds.Round {
	if round.PrepareNextRound() {
		return &round2{round}
	}
	return round
}
