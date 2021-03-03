package sign

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type (
	round0 struct {
		*rounds.Parameters

		// Message is the message to be signed
		Message []byte

		// Parties maps IDs to a struct containing all intermediary data for each signer.
		Parties map[uint32]*signer

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
	*rounds.BaseOutput
	Signature *eddsa.Signature
}

func NewRound(params *rounds.Parameters, secret *eddsa.PrivateKey, shares *eddsa.Shares, message []byte) (rounds.Round, *Output, error) {
	var (
		round round0
		err   error
	)

	partyIDs := params.AllPartyIDs()
	selfID := params.SelfID()

	round.Parameters = params
	round.Message = message

	// Get the group key from the shares
	round.GroupKey = shares.GroupKey()

	round.Parties = make(map[uint32]*signer, params.N())
	for _, id := range partyIDs {
		var party signer
		if id == 0 {
			return nil, nil, errors.New("id 0 is not valid")
		}
		party.Public, err = shares.ShareNormalized(id, partyIDs)
		if err != nil {
			return nil, nil, err
		}
		round.Parties[id] = &party
	}
	if _, ok := round.Parties[selfID]; !ok {
		return nil, nil, errors.New("secret data and ID don't match")
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := shares.Lagrange(selfID, partyIDs)
	if err != nil {
		return nil, nil, err
	}
	round.SecretKeyShare.Multiply(lagrange, secret.Scalar())

	output := &Output{BaseOutput: rounds.NewBaseOutput()}
	round.Output = output

	return &round, output, nil
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
