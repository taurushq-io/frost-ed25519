package keygen

import (
	"errors"
	"sync"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/common"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/zk"
)

type base struct {
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

	// msgs1, msgs2 contain the messages received from the other parties.
	msgs1 map[uint32]*messages.KeyGen1
	msgs2 map[uint32]*messages.KeyGen2

	readyForNextRound bool
	sync.Mutex
}

func (round *base) StoreMessage(message *messages.Message) error {
	round.Lock()
	defer round.Unlock()

	if message.KeyGen1 == nil && message.KeyGen2 == nil {
		return frost.ErrNoSignContent
	}

	if message.From == round.PartySelf {
		return nil
	}

	if !round.isOtherParticipant(message.From) {
		return frost.ErrInvalidSender
	}

	switch message.Type {
	case messages.MessageTypeKeyGen1:
		if _, ok := round.msgs1[message.From]; ok {
			return frost.ErrDuplicateMessage
		}
		round.msgs1[message.From] = message.KeyGen1
		return nil

	case messages.MessageTypeKeyGen2:
		if _, ok := round.msgs2[message.From]; ok {
			return frost.ErrDuplicateMessage
		}
		round.msgs2[message.From] = message.KeyGen2
		return nil
	}

	return frost.ErrMessageStore
}

func (round *base) CanProcess() bool {
	return !round.readyForNextRound
}

func (round *base) ProcessRound() ([]*messages.Message, error) {
	var secret edwards25519.Scalar
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		return nil, frost.ErrRoundProcessed
	}

	// Sample a_i,0
	common.SetScalarRandom(&secret)

	// Sample the remaining coefficients
	round.Polynomial = polynomial.NewPolynomial(round.Threshold, &secret)

	// Generate proof of knowledge of a_i,0
	proof, _ := zk.NewSchnorrProof(&secret, round.PartySelf, "")

	// Generate all commitments [a_i,j] B for j = 0, 1, ..., t
	round.CommitmentsSum = polynomial.NewPolynomialExponent(round.Polynomial)

	msg := messages.NewKeyGen1(round.PartySelf, proof, round.CommitmentsSum)

	round.readyForNextRound = true

	return []*messages.Message{msg}, nil
}

func (round *base) NextRound() frost.Round {
	round.Lock()
	defer round.Unlock()

	if round.readyForNextRound {
		round.readyForNextRound = false
		return &round1{round}
	}

	return round
}

func (round *base) Reset() {
	round.Lock()
	defer round.Unlock()
}

func NewRound(selfID uint32, threshold uint32, partyIDs []uint32) (frost.Round, error) {
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

	N := len(partyIDs)
	r := base{
		PartySelf:         selfID,
		OtherParties:      othersMap,
		Threshold:         threshold,
		CommitmentsOthers: make(map[uint32]*polynomial.Exponent, N),
		msgs1:             make(map[uint32]*messages.KeyGen1, N),
		msgs2:             make(map[uint32]*messages.KeyGen2, N),
	}

	return &r, nil
}

// isOtherParticipant indicates whether p is one of the parties we are currently signing with.
func (round *base) isOtherParticipant(p uint32) bool {
	if p == round.PartySelf {
		return false
	}
	_, ok := round.OtherParties[p]

	return ok
}

func (round *base) ID() uint32 {
	return round.PartySelf
}
