package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round2) ProcessMessage(msg *messages.Message) *rounds.Error {
	var computedShareExp edwards25519.Point
	computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

	id := msg.From
	shareExp := round.Commitments[id].Evaluate(round.SelfID().Scalar())

	if computedShareExp.Equal(shareExp) != 1 {
		return rounds.NewError(id, errors.New("VSS failed to validate"))
	}
	round.Secret.Add(&round.Secret, &msg.KeyGen2.Share)

	// We can reset the share in the message now
	msg.KeyGen2.Share.Set(edwards25519.NewScalar())

	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	shares := make(map[party.ID]*edwards25519.Point, round.Set().N())
	for id := range round.Set().Range() {
		shares[id] = round.CommitmentsSum.Evaluate(id.Scalar())
	}
	round.Output.Shares = eddsa.NewShares(shares, round.Threshold, round.CommitmentsSum.Constant())
	round.Output.SecretKey = eddsa.NewSecretShare(round.SelfID(), &round.Secret)
	return nil, nil
}

func (round *round2) NextRound() rounds.Round {
	return nil
}

func (round *round2) MessageType() messages.MessageType {
	return messages.MessageTypeKeyGen2
}
