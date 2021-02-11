package keygen

import (
	"errors"
	"fmt"
	"sync"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
)

type (
	base struct {
		PartySelf uint32

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

		// OtherParties is a sorted array of party IDs
		OtherParties map[uint32]struct{}

		// Threshold is the degree of the polynomial used for Shamir.
		// It is the number of tolerated party corruptions.
		Threshold uint32

		messages *messages.Queue

		messagesProcessed, roundProcessed bool

		output chan struct{}

		// GroupKey is the public key for the entire group.
		// It is Shamir shared.
		GroupKey *eddsa.PublicKey

		// GroupKeyShares are the Shamir shares of the public key,
		// "in-the-exponent".
		GroupKeyShares map[uint32]*eddsa.PublicKey

		sync.Mutex
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
)

func NewRound(selfID uint32, threshold uint32, partyIDs []uint32) (frost.KeyGenRound, error) {
	if selfID == 0 {
		return nil, errors.New("id 0 is not valid")
	}

	// Remove all duplicates and occurrences of selfID from partyIDs
	othersMap := map[uint32]struct{}{}
	for _, id := range partyIDs {
		if selfID == id {
			continue
		}
		othersMap[id] = struct{}{}
	}

	accepted := []messages.MessageType{messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}
	messagesHolder, err := messages.NewMessageHolder(selfID, othersMap, accepted)
	if err != nil {
		return nil, fmt.Errorf("failed to create messageHolder: %w", err)
	}

	N := len(partyIDs)
	r := base{
		PartySelf:         selfID,
		OtherParties:      othersMap,
		Threshold:         threshold,
		CommitmentsOthers: make(map[uint32]*polynomial.Exponent, N),
		messages:          messagesHolder,
		output:            make(chan struct{}),
		GroupKeyShares:    make(map[uint32]*eddsa.PublicKey, N),
	}

	return &r, nil
}

func (round *base) StoreMessage(message *messages.Message) error {
	return round.messages.Store(message)
}

func (round *base) ID() uint32 {
	return round.PartySelf
}

func (round *base) Reset() {
}

func (round *base) CanStart() bool {
	return true
}

func (round *round1) CanStart() bool {
	round.Lock()
	defer round.Unlock()
	return round.messages.ReceivedAll()
}
