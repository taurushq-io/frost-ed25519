package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

type round2 struct {
	*round1
}

func (round *round2) CanProcess() bool {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return false
	}

	if len(round.msgs2) == len(round.OtherParties) {
		for id := range round.OtherParties {
			if _, ok := round.msgs2[id]; !ok {
				return false
			}
		}
	}
	return true
}

func (round *round2) ProcessMessages() error {
	var computedShareExp edwards25519.Point
	for id := range round.OtherParties {
		msg := round.msgs2[id]

		shareExp := round.CommitmentsOthers[id].Evaluate(round.PartySelf)
		computedShareExp.ScalarBaseMult(msg.Share)

		if computedShareExp.Equal(shareExp) != 1 {
			return errors.New("VSS failed to validate")
		}

		round.Secret.Add(&round.Secret, msg.Share)

		delete(round.msgs2, id)
	}
	return nil
}

func (round *round2) ProcessRound() ([]*messages.Message, error) {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return nil, frost.ErrRoundProcessed
	}

	if err := round.ProcessMessages(); err != nil {
		return nil, err
	}

	round.readyForNextRound = true

	publicShares := make(map[uint32]*eddsa.PublicKey, len(round.OtherParties)+1)
	for id := range round.OtherParties {
		publicShares[id] = &eddsa.PublicKey{Point: *round.CommitmentsSum.Evaluate(id)}
	}
	publicShares[round.PartySelf] = &eddsa.PublicKey{Point: *round.CommitmentsSum.Evaluate(round.PartySelf)}

	groupKey := &eddsa.PublicKey{Point: *round.CommitmentsSum.Evaluate(0)}
	msgOut := messages.NewKeyGenOutput(round.ID(), groupKey, publicShares, &round.Secret)

	return []*messages.Message{msgOut}, nil
}
func (round *round2) NextRound() frost.Round {
	return round
}
