package sign

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type (
	round0 struct {
		partySet *party.SetWithSelf

		// Message is the message to be signed
		Message []byte

		// Parties maps IDs to a struct containing all intermediary data for each signer.
		Parties map[party.ID]*signer

		// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
		GroupKey       *eddsa.PublicKey
		SecretKeyShare edwards25519.Scalar

		// e and d are the scalars committed to in the first round
		e, d edwards25519.Scalar

		// C = H(R, GroupKey, Message)
		C edwards25519.Scalar
		// R = ∑ Ri
		R edwards25519.Point

		Output *Output
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

type Output struct {
	Signature *eddsa.Signature
}

func NewRound(partySet *party.SetWithSelf, secret *eddsa.PrivateKey, shares *eddsa.Shares, message []byte) (rounds.Round, *Output, error) {
	round := &round0{
		partySet: partySet,
		Message:  message,
		Parties:  make(map[party.ID]*signer, partySet.N()),
		GroupKey: shares.GroupKey(),
		Output:   &Output{},
	}

	partyIDs := partySet.Sorted()
	// Setup parties
	for id := range partySet.Range() {
		if id == 0 {
			return nil, nil, errors.New("id 0 is not valid")
		}

		shareNormalized, err := shares.ShareNormalized(id, partyIDs)
		if err != nil {
			return nil, nil, err
		}
		round.Parties[id] = &signer{
			Public: shareNormalized,
		}
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := shares.Lagrange(partySet.Self(), partyIDs)
	if err != nil {
		return nil, nil, err
	}
	round.SecretKeyShare.Multiply(lagrange, secret.Scalar())

	return round, round.Output, nil
}

func (round *round0) Reset() {
	zero := edwards25519.NewScalar()
	one := edwards25519.NewIdentityPoint()

	round.Message = nil
	round.SecretKeyShare.Set(zero)

	round.e.Set(zero)
	round.d.Set(zero)
	round.C.Set(zero)
	round.R.Set(one)

	for id, p := range round.Parties {
		p.Reset()
		delete(round.Parties, id)
	}
}

var acceptedMessageTypes = []messages.MessageType{
	messages.MessageTypeSign1,
	messages.MessageTypeSign2,
}

func (round *round0) AcceptedMessageTypes() []messages.MessageType {
	return acceptedMessageTypes
}
