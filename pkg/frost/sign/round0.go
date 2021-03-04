package sign

import (
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func (round *round0) ProcessMessage(msg *messages.Message) *rounds.Error {
	return nil
}

func (round *round0) GenerateMessages() ([]*messages.Message, *rounds.Error) {
	selfParty := round.Parties[round.partySet.Self()]

	// Sample d_i, D_i = [d_i] B
	scalar.SetScalarRandom(&round.d)
	selfParty.Di.ScalarBaseMult(&round.d)

	// Sample e_i, D_i = [e_i] B
	scalar.SetScalarRandom(&round.e)
	selfParty.Ei.ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.partySet.Self(), &selfParty.Di, &selfParty.Ei)

	return []*messages.Message{msg}, nil
}

func (round *round0) NextRound() rounds.Round {
	return &round1{round}
}
