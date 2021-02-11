package sign

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

var ErrValidateSigShare = errors.New("failed to validate sig share")

//func (round *round2) CanStart() bool {
//	if len(round.msgs2) == len(round.AllParties)-1 {
//		return false
//	}
//	for id := range round.Parties {
//		if id == round.PartySelf {
//			continue
//		}
//		if _, ok := round.msgs2[id]; !ok {
//			return false
//		}
//	}
//	return true
//}

func (round *round2) ProcessMessages() error {
	round.Lock()
	defer round.Unlock()

	if round.messagesProcessed {
		return nil
	}

	msgs := round.messages.Messages()

	var RPrime edwards25519.Point
	var CNeg edwards25519.Scalar

	CNeg.Negate(&round.C)

	for id, msg := range msgs {
		party := round.Parties[id]

		// We have already multiplied the public key by the lagrange coefficient,
		// so we we simply check
		//
		// 	R' =  [-c] Y + [z] B = [-c * 𝛌] [x] B + [z] B
		//     =  [-c * 𝛌 * x + z] B
		//  R =? R'
		//
		RPrime.VarTimeDoubleScalarBaseMult(&CNeg, &party.Public, &msg.Sign2.Zi)
		if RPrime.Equal(&party.Ri) != 1 {
			return fmt.Errorf("party %d: %w", id, ErrValidateSigShare)
		}
	}

	for id, party := range round.Parties {
		if id == round.PartySelf {
			continue
		}
		party.Zi.Set(&msgs[id].Sign2.Zi)
	}

	round.messagesProcessed = true

	return nil
}

func (round *round2) ProcessRound() error {
	round.Lock()
	defer round.Unlock()

	if round.roundProcessed {
		return frost.ErrRoundProcessed
	}

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
		RPrime.VarTimeDoubleScalarBaseMult(&CNeg, &round.Y, &sig)
		if RPrime.Equal(&round.R) != 1 {
			return fmt.Errorf("party %d: %w", round.PartySelf, ErrValidateSigShare)
		}
	}

	round.Signature = &eddsa.Signature{
		R: round.R,
		S: sig,
	}

	close(round.output)
	round.roundProcessed = true

	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, error) {
	return nil, nil
}

func (round *round2) NextRound() frost.Round {
	return round
}

func (round *base) WaitForSignOutput() (signature *eddsa.Signature) {
	if round.Signature != nil {
		return round.Signature
	}
	<-round.output
	return round.Signature
}
