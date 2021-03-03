package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round2) ProcessMessage(msg *messages.Message) *rounds.Error {
	var computedShareExp edwards25519.Point
	computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

	id := msg.From
	shareExp := round.Commitments[id].Evaluate(round.SelfID())

	if computedShareExp.Equal(shareExp) != 1 {
		err := rounds.NewError(id, errors.New("VSS failed to validate"))
		round.Output.Abort(err)
		return err
	}

	round.Secret.Add(&round.Secret, &msg.KeyGen2.Share)

	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	shares := make(map[uint32]*edwards25519.Point, round.N())
	for _, id := range round.AllPartyIDs() {
		shares[id] = round.CommitmentsSum.Evaluate(id)
	}
	round.Output.Shares = eddsa.NewShares(shares, round.Threshold, round.CommitmentsSum.Constant())
	round.Output.SecretKey = eddsa.NewPrivateKeyFromScalar(&round.Secret)
	round.Output.Abort(nil)
	return nil, nil
}

func (round *round2) NextRound() rounds.Round {
	return nil
}

func (round *round2) MessageType() messages.MessageType {
	return messages.MessageTypeKeyGen2
}
