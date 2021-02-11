package keygen

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
)

func (round *round1) ProcessMessages() error {
	round.Lock()
	defer round.Unlock()

	if round.messagesProcessed {
		return nil
	}

	msgs := round.messages.Messages()

	for _, msg := range msgs {
		if !msg.KeyGen1.Proof.Verify(msg.KeyGen1.Commitments.Evaluate(0), msg.From, "") {
			return errors.New("ZK Schnorr failed")
		}
	}

	for id := range round.OtherParties {
		msg := msgs[id].KeyGen1

		// Add the commitments to our own, so that we can interpolate the final polynomial
		err := round.CommitmentsSum.Add(msg.Commitments)
		if err != nil {
			return err
		}

		round.CommitmentsOthers[id] = msg.Commitments
	}

	round.messages.NextRound()
	round.messagesProcessed = true

	return nil
}

func (round *round1) ProcessRound() error {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed {
		return nil
	}

	// We use the variable Secret to hold the sum of all shares received.
	// Therefore, we can set it to the share we would send to our selves.
	round.Secret.Set(round.Polynomial.Evaluate(round.PartySelf))

	round.roundProcessed = true

	return nil
}

func (round *round1) GenerateMessages() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if !(round.roundProcessed && round.messagesProcessed) {
		return nil, frost.ErrRoundNotProcessed
	}

	msgsOut := make([]*messages.Message, 0, len(round.OtherParties))
	for id := range round.OtherParties {
		msgsOut = append(msgsOut, messages.NewKeyGen2(round.PartySelf, id, round.Polynomial.Evaluate(id)))
	}
	return msgsOut, nil
}

func (round *round1) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed && round.messagesProcessed {
		// Now that we have received the commitment from every one,
		// we no longer require the original polynomial, so we reset it
		round.Polynomial.Reset()
		round.Polynomial = nil

		round.roundProcessed = false
		round.messagesProcessed = false
		return &round2{round}
	}
	return round
}
