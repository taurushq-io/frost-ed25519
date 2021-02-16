package keygen

import (
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type (
	round0 struct {
		*rounds.BaseRound

		// Secret is first set to the zero coefficient of the polynomial we send to the other parties.
		// Once all received shares are declared, they are summed here to produce the party's
		// final secret key.
		Secret edwards25519.Scalar

		// Polynomial used to sample shares
		Polynomial *polynomial.Polynomial
		// CommitmentsSum is the sum of all commitments, we use it to compute public key shares
		CommitmentsSum *polynomial.Exponent
		// CommitmentsOthers contains all other parties commitment polynomials
		CommitmentsOthers map[uint32]*polynomial.Exponent

		// Threshold is the degree of the polynomial used for Shamir.
		// It is the number of tolerated party corruptions.
		Threshold uint32

		// GroupKey is the public key for the entire group.
		// It is Shamir shared.
		GroupKey *eddsa.PublicKey

		// GroupKeyShares are the Shamir shares of the public key,
		// "in-the-exponent".
		GroupKeyShares eddsa.PublicKeyShares

		// SecretKeyShare is the party's Shamir share of the secret of the GroupKey.
		SecretKeyShare *eddsa.PrivateKey
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

func NewRound(selfID uint32, threshold uint32, partyIDs []uint32) (rounds.KeyGenRound, error) {
	accepted := []messages.MessageType{messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}
	baseRound, err := rounds.NewBaseRound(selfID, partyIDs, accepted)
	if err != nil {
		return nil, fmt.Errorf("failed to create messageHolder: %w", err)
	}

	N := len(partyIDs)
	r := round0{
		BaseRound:         baseRound,
		Threshold:         threshold,
		CommitmentsOthers: make(map[uint32]*polynomial.Exponent, N),
		GroupKeyShares:    make(eddsa.PublicKeyShares, N),
	}

	return &r, nil
}

func (round *round0) WaitForKeygenOutput() (groupKey *eddsa.PublicKey, groupKeyShares eddsa.PublicKeyShares, secretKeyShare *eddsa.PrivateKey, err error) {
	err = round.WaitForFinish()
	round.Reset()
	if err != nil {
		return nil, nil, nil, err
	}
	return round.GroupKey, round.GroupKeyShares, round.SecretKeyShare, nil
}

func (round *round0) Reset() {
	zero := edwards25519.NewScalar()

	round.Secret.Set(zero)
	if round.Polynomial != nil {
		round.Polynomial.Reset()
	}
	round.CommitmentsSum.Reset()
	for id, p := range round.CommitmentsOthers {
		p.Reset()
		delete(round.CommitmentsOthers, id)
	}
}
