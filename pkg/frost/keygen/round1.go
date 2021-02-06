package keygen

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
)

type round1 struct {
	*base
}

func (round *round1) CanProcess() bool {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return false
	}

	// Check that we have received a message from everyone
	if len(round.msgs1) == len(round.OtherParties) {
		for id := range round.OtherParties {
			if _, ok := round.msgs1[id]; !ok {
				return false
			}
		}
	}




	return true
}

func (round *round1) ProcessMessages() error {
	for id := range round.OtherParties {
		msg := round.msgs1[id]

		if !msg.Proof.Verify(msg.Commitments.Evaluate(0), id, "") {
			a := msg.Commitments.Evaluate(0)
			msg.Proof.Verify(a, id, "")
			return errors.New("ZK Schnorr failed")
		}

		// Add the commitments to our own, so that we can interpolate the final polynomial
		if err := round.CommitmentsSum.Add(msg.Commitments); err != nil {
			return err
		}

		round.CommitmentsOthers[id] = msg.Commitments

		//delete(round.msgs1, id)
	}
	return nil
}

func (round *round1) ProcessRound() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return nil, frost.ErrRoundProcessed
	}

	if err := round.ProcessMessages(); err != nil {
		return nil, err
	}

	round.Secret.Set(round.Polynomial.Evaluate(round.PartySelf))

	msgsOut := make([]*messages.Message, 0, len(round.OtherParties))
	for id := range round.OtherParties {
		msgsOut = append(msgsOut, messages.NewKeyGen2(round.PartySelf, id, round.Polynomial.Evaluate(id)))
	}

	round.readyForNextRound = true

	return msgsOut, nil
}
func (round *round1) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		round.readyForNextRound = false
		return &round2{round}
	}
	return round
}
