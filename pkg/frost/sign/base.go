package sign

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type (
	round0 struct {
		*state.BaseRound

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

func NewRound(partySet *party.Set, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (state.Round, *Output, error) {
	if !partySet.Contains(secret.ID) {
		return nil, nil, errors.New("owner of SecretShare is not contained in partySet")
	}
	if !partySet.IsSubsetOf(shares.PartySet) {
		return nil, nil, errors.New("not all parties of partySet are contained in shares")
	}

	baseRound, err := state.NewBaseRound(secret.ID, partySet)
	if err != nil {
		return nil, nil, err
	}

	round := &round0{
		BaseRound: baseRound,
		Message:   message,
		Parties:   make(map[party.ID]*signer, partySet.N()),
		GroupKey:  shares.GroupKey(),
		Output:    &Output{},
	}

	// Setup parties
	for id := range partySet.Range() {
		if id == 0 {
			return nil, nil, errors.New("id 0 is not valid")
		}

		shareNormalized, err := shares.ShareNormalized(id, partySet)
		if err != nil {
			return nil, nil, err
		}
		round.Parties[id] = &signer{
			Public: shareNormalized,
		}
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := partySet.Lagrange(round.SelfID())
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
	round.Output = nil
}

func (round *round0) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{
		messages.MessageTypeSign1,
		messages.MessageTypeSign2,
	}
}
