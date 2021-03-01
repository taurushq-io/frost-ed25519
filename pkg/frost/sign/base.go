package sign

import (
	"errors"
	"fmt"
	"time"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type (
	round0 struct {
		*rounds.BaseRound

		// Message is the message to be signed
		Message []byte

		// Parties maps IDs to a struct containing all intermediary data for each signer.
		Parties map[uint32]*signer

		// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
		GroupKey       edwards25519.Point
		SecretKeyShare edwards25519.Scalar

		// e and d are the scalars committed to in the first round
		e, d edwards25519.Scalar

		// C = H(R, GroupKey, Message)
		C edwards25519.Scalar
		// R = ∑ Ri
		R edwards25519.Point

		// Signature is the output
		Signature *eddsa.Signature
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

func NewRound(selfID uint32, partyIDs []uint32, secret *eddsa.PrivateKey, shares *eddsa.Shares, message []byte, messageTimeout, globalTimeout time.Duration) (rounds.Round, error) {
	var (
		round round0
		err   error
	)

	round.GroupKey.Set(edwards25519.NewIdentityPoint())
	round.Parties = make(map[uint32]*signer, len(partyIDs))
	for _, id := range partyIDs {
		var party signer
		if id == 0 {
			return nil, errors.New("id 0 is not valid")
		}
		publicKeyNormalized, err := shares.ShareNormalized(id, partyIDs)
		if err != nil {
			return nil, err
		}

		party.Public.Set(publicKeyNormalized.Point())

		round.GroupKey.Add(&round.GroupKey, &party.Public)

		round.Parties[id] = &party
	}
	if _, ok := round.Parties[selfID]; !ok {
		return nil, errors.New("secret data and ID don't match")
	}

	accepted := []messages.MessageType{messages.MessageTypeSign1, messages.MessageTypeSign2}
	round.BaseRound, err = rounds.NewBaseRound(selfID, partyIDs, accepted, messageTimeout, globalTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create messageHolder: %w", err)
	}

	round.Message = message

	round.SecretKeyShare.Multiply(polynomial.LagrangeCoefficient(selfID, partyIDs), secret.Scalar())

	return &round, nil
}

func (round *round0) WaitForSignOutput() (signature *eddsa.Signature, err error) {
	err = round.WaitForFinish()
	round.Reset()
	if err != nil {
		return nil, err
	}

	return round.Signature, nil
}

func (round *round0) Reset() {
	zero := edwards25519.NewScalar()
	one := edwards25519.NewIdentityPoint()

	round.Message = nil
	round.GroupKey.Set(one)
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
