package keygen

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round2) ProcessMessages() {
	if !round.CanProcessMessages() {
		return
	}
	defer round.NextStep()

	msgs := round.Messages()

	var computedShareExp edwards25519.Point
	for id, msg := range msgs {
		shareExp := round.CommitmentsOthers[id].Evaluate(round.ID())
		computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

		if computedShareExp.Equal(shareExp) != 1 {
			round.Abort(id, errors.New("VSS failed to validate"))
		}
	}

	for id := range round.OtherPartyIDs {
		round.Secret.Add(&round.Secret, &msgs[id].KeyGen2.Share)
	}
}

func (round *round2) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.Finish()

	for id := range round.OtherPartyIDs {
		round.GroupKeyShares[id] = eddsa.NewPublicKeyFromPoint(round.CommitmentsSum.Evaluate(id))
	}
	round.GroupKeyShares[round.ID()] = eddsa.NewPublicKeyFromPoint(round.CommitmentsSum.Evaluate(round.ID()))
	round.GroupKey = eddsa.NewPublicKeyFromPoint(round.CommitmentsSum.Evaluate(0))
	round.SecretKeyShare = eddsa.NewPrivateKeyFromScalar(&round.Secret, round.GroupKeyShares[round.ID()])
}

func (round *round2) GenerateMessages() []*messages.Message {
	return nil
}

func (round *round2) NextRound() rounds.Round {
	return round
}
