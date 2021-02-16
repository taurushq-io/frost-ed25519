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

	var RPrime edwards25519.Point
	var CNeg edwards25519.Scalar

	CNeg.Negate(&round.C)

	for id, msg := range msgs {
		party := round.Parties[id]

		// We have already multiplied the public key by the lagrange coefficient,
		// so we we simply check
		//
		// 	R' =  [-c] GroupKey + [z] B = [-c * 𝛌] [x] B + [z] B
		//     =  [-c * 𝛌 * x + z] B
		//  R =? R'
		//
		RPrime.VarTimeDoubleScalarBaseMult(&CNeg, &party.Public, &msg.Sign2.Zi)
		if RPrime.Equal(&party.Ri) != 1 {
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

	return
}

func (round *round2) ProcessRound() {
	if !round.CanProcessRound() {
		return
	}
	defer round.NextStep()
	defer round.Finish()

	var sig, CNeg edwards25519.Scalar
	var RPrime edwards25519.Point

	// sig = s = ∑ s_i
	{
		sig.Set(edwards25519.NewScalar())
		for _, party := range round.Parties {
			// s += s_i
			sig.Add(&sig, &party.Zi)
		}
	}

	// Verify the full signature here too.
	{
		CNeg.Negate(&round.C)
		RPrime.VarTimeDoubleScalarBaseMult(&CNeg, &round.GroupKey, &sig)
		if RPrime.Equal(&round.R) != 1 {
			round.Abort(0, ErrValidateSignature)
			return
		}
	}

	round.Signature = &eddsa.Signature{
		R: round.R,
		S: sig,
	}
	return
}

func (round *round2) GenerateMessages() []*messages.Message {
	return nil
}

func (round *round2) NextRound() rounds.Round {
	return round
}
