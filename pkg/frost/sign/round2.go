package sign

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

var (
	ErrValidateSigShare  = errors.New("signature share is invalid")
	ErrValidateSignature = errors.New("full signature is invalid")
)

func (round *round2) ProcessMessages() {
	if !round.CanProcessMessages() {
		return
	}
	defer round.NextStep()

	msgs := round.Messages()

	for id, msg := range msgs {
		party := round.Parties[id]

		if !eddsa.Verify(&round.C, &msg.Sign2.Zi, party.Public, &party.Ri) {
			round.Abort(id, ErrValidateSigShare)
			return
		}
	}

	for id, party := range round.Parties {
		if id == round.ID() {
			continue
		}
		party.Zi.Set(&msgs[id].Sign2.Zi)
	}
}

func (round *round2) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()
	defer round.Finish()

	var S edwards25519.Scalar

	// S = ∑ s_i
	{
		S.Set(edwards25519.NewScalar())
		for _, party := range round.Parties {
			// s += s_i
			S.Add(&S, &party.Zi)
		}
	}

	Signature := &eddsa.Signature{
		R: round.R,
		S: S,
	}

	// Verify the full signature here too.
	if !Signature.Verify(round.Message, round.GroupKey) {
		round.Abort(0, ErrValidateSignature)
		return
	}

	round.Signature = Signature
}

func (round *round2) GenerateMessages() []*messages.Message {
	return nil
}

func (round *round2) NextRound() rounds.Round {
	return round
}
