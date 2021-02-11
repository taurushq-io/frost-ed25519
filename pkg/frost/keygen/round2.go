package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

func (round *round2) ProcessMessages() error {
	round.Lock()
	defer round.Unlock()

	if round.messagesProcessed {
		return nil
	}

	msgs := round.messages.Messages()

	var computedShareExp edwards25519.Point
	for id, msg := range msgs {

		shareExp := round.CommitmentsOthers[id].Evaluate(round.PartySelf)
		computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

		if computedShareExp.Equal(shareExp) != 1 {
			return errors.New("VSS failed to validate")
		}
	}

	for id := range round.OtherParties {
		round.Secret.Add(&round.Secret, &msgs[id].KeyGen2.Share)
	}

	round.messages.NextRound()
	round.messagesProcessed = true

	return nil
}

func (round *round2) ProcessRound() error {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed {
		return nil
	}

	for id := range round.OtherParties {
		round.GroupKeyShares[id] = &eddsa.PublicKey{Point: round.CommitmentsSum.Evaluate(id)}
	}
	round.GroupKeyShares[round.PartySelf] = &eddsa.PublicKey{Point: round.CommitmentsSum.Evaluate(round.PartySelf)}
	round.GroupKey = &eddsa.PublicKey{Point: round.CommitmentsSum.Evaluate(0)}

	round.roundProcessed = true
	close(round.output)
	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, error) {
	return nil, nil
}

func (round *round2) NextRound() frost.Round {
	return round
}

func (round *base) WaitForKeyGenOutput() (groupKey *eddsa.PublicKey, groupKeyShares map[uint32]*eddsa.PublicKey, secretKeyShare edwards25519.Scalar, err error) {
	// TODO handle cancel

	if round.GroupKey != nil {
		return round.GroupKey, round.GroupKeyShares, round.Secret, nil
	}

	<-round.output
	return round.GroupKey, round.GroupKeyShares, round.Secret, nil
}
