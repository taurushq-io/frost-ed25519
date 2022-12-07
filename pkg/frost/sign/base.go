package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type ProtocolVersion int

const (
	FROST_1 ProtocolVersion = iota
	FROST_2
)

type (
	round0 struct {
		*state.BaseRound

		Version ProtocolVersion

		// Message is the message to be signed
		Message []byte

		// Parties maps IDs to a struct containing all intermediary data for each signer.
		Parties map[party.ID]*signer

		// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
		GroupKey       eddsa.PublicKey
		SecretKeyShare ristretto.Scalar

		// e and d are the scalars committed to in the first round
		e, d ristretto.Scalar

		// C = H(R, GroupKey, Message)
		C ristretto.Scalar
		// R = ∑ Ri
		R ristretto.Element
		// if the protocol version is FROST2
		// P = ρ = H(Message, B)
		// This does means there is one global shift for the nonces instead of one for each signer
		// This allows for 1 group exponentiation instead of t
		P ristretto.Scalar

		Output *Output
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

func NewRound(version ProtocolVersion, partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (state.Round, *Output, error) {
	if !partyIDs.Contains(secret.ID) {
		return nil, nil, errors.New("base.NewRound: owner of SecretShare is not contained in partyIDs")
	}
	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, errors.New("base.NewRound: not all parties of partyIDs are contained in shares")
	}

	baseRound, err := state.NewBaseRound(secret.ID, partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}

	round := &round0{
		BaseRound: baseRound,
		Version:   version,
		Message:   message,
		Parties:   make(map[party.ID]*signer, partyIDs.N()),
		GroupKey:  *shares.GroupKey,
		Output:    &Output{},
	}

	// Setup parties
	for _, id := range partyIDs {
		var s signer
		if id == 0 {
			return nil, nil, errors.New("base.NewRound: id 0 is not valid")
		}
		originalShare := shares.Shares[id]
		lagrange, err := id.Lagrange(partyIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("base.NewRound: %w", err)
		}
		s.Public.ScalarMult(lagrange, originalShare)
		round.Parties[id] = &s
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := round.SelfID().Lagrange(partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}
	round.SecretKeyShare.Multiply(lagrange, &secret.Secret)

	return round, round.Output, nil
}

func (round *round0) Reset() {
	zero := ristretto.NewScalar()
	one := ristretto.NewIdentityElement()

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
		messages.MessageTypeNone,
		messages.MessageTypeSign1,
		messages.MessageTypeSign2,
	}
}
