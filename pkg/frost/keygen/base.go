package keygen

import (
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
		GroupKeyShares map[uint32]*edwards25519.Point

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

func NewRound(selfID uint32, threshold uint32, partyIDs []uint32, timeout time.Duration) (rounds.KeyGenRound, error) {
	accepted := []messages.MessageType{messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}
	baseRound, err := rounds.NewBaseRound(selfID, partyIDs, accepted, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create messageHolder: %w", err)
	}

	if int(threshold) >= len(partyIDs) {
		return nil, fmt.Errorf("threshold %d is invalid with number of signers %d", threshold, len(partyIDs))
	}

	N := len(partyIDs)

	if int(threshold) == 0 {
		return nil, fmt.Errorf("threshold must be at least 1, or a minimum of T+1=2 signers")
	}
	if int(threshold) > N-1 {
		return nil, fmt.Errorf("threshold must be at most N-1, or a maximum of T+1=N signers")
	}

	r := round0{
		BaseRound:         baseRound,
		Threshold:         threshold,
		CommitmentsOthers: make(map[uint32]*polynomial.Exponent, N),
		GroupKeyShares:    make(map[uint32]*edwards25519.Point, N),
	}

	return &r, nil
}

func (round *round0) Output() (*eddsa.PublicKey, *eddsa.Shares, *eddsa.PrivateKey) {
	round.Reset()
	return round.GroupKey, eddsa.NewShares(round.GroupKeyShares, round.Threshold), round.SecretKeyShare
}

func (round *round0) Reset() {
	round.Secret.Set(edwards25519.NewScalar())
	if round.Polynomial != nil {
		round.Polynomial.Reset()
	}
	if round.CommitmentsSum != nil {
		round.CommitmentsSum.Reset()
	}
	for _, p := range round.CommitmentsOthers {
		if p != nil {
			p.Reset()
		}
	}
}
