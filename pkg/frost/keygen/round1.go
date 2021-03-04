package keygen

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round1) ProcessMessage(msg *messages.Message) *rounds.Error {
	// TODO we can use custom contexts to prevent replay attacks
	ctx := make([]byte, 32)

	public := msg.KeyGen1.Commitments.Constant()
	if !msg.KeyGen1.Proof.Verify(msg.From, public, ctx) {
		return rounds.NewError(msg.From, errors.New("ZK Schnorr failed"))
	}

	round.Commitments[msg.From] = msg.KeyGen1.Commitments

	// Add the commitments to our own, so that we can interpolate the final polynomial
	_ = round.CommitmentsSum.Add(msg.KeyGen1.Commitments)
	return nil
}

func (round *round1) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	msgsOut := make([]*messages.Message, 0, round.N()-1)
	for _, id := range round.AllPartyIDs() {
		if id == round.SelfID() {
			continue
		}
		msgsOut = append(msgsOut, messages.NewKeyGen2(round.SelfID(), id, round.Polynomial.Evaluate(id.Scalar())))
	}

	// Now that we have received the commitment from every one,
	// we no longer require the original polynomial, so we reset it
	round.Polynomial.Reset()

	return msgsOut, nil
}

func (round *round1) NextRound() rounds.Round {
	return &round2{round}
}

func (round *round1) MessageType() messages.MessageType {
	return messages.MessageTypeKeyGen1
}
