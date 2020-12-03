package frost

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"
	"github.com/taurusgroup/tg-tss/pkg/helpers/vss"
	"github.com/taurusgroup/tg-tss/pkg/helpers/zk"
	"math/big"
)

// TODO this is temporary, it would probably be best to do something a la GGCMP with sessions etc
var params = ""

var (
	ErrInvalidSchnorr = errors.New("invalid Schnorr proof")
	ErrMissingValues  = errors.New("missing inputs")
	ErrDuplicateInput = errors.New("already received input")
	ErrInvalidVSS     = errors.New("bad VSS input")
)

type (
	round1 struct {
		PartyID common.Party
		Parties []common.Party

		PrivateKeyShare *big.Int
		PublicKeyShare  common.PublicKeyShare

		Threshold uint32

		VSSCommitments vss.Commitments
		VSSShares      []vss.Share

		SchnorrProof zk.Schnorr
	}
	InputRound2 struct {
		SchnorrProof   zk.Schnorr
		VSSCommitments vss.Commitments
	}
	round2 struct {
		ReceivedCommitments map[common.Party]*InputRound2
		*round1
	}
	InputRound3 struct {
		Share vss.Share
	}
	round3 struct {
		ReceivedShares map[common.Party]*vss.Share
		*round2
	}
	KeyGenOutput struct {
		PublicKeys []common.PublicKeyShare
		PrivateKey *big.Int
	}
)

func StartRound1(partyId common.Party, parties []common.Party, threshold uint32) (*round1, error) {

	secretKey, err := rand.Int(rand.Reader, curve.Modulus())
	if err != nil {
		return nil, fmt.Errorf("round1: start: %w", err)
	}

	secretShares, vssCommitments, err := vss.New(secretKey, threshold, parties)
	if err != nil {
		return nil, fmt.Errorf("round1: start: vss: %w", err)
	}

	_, proof, err := zk.NewSchnorr(secretKey, partyId, params)
	if err != nil {
		return nil, err
	}

	return &round1{
		PartyID: partyId,
		Parties: parties,

		PrivateKeyShare: secretKey,

		Threshold: threshold,

		VSSCommitments: vssCommitments,
		VSSShares:      secretShares,

		SchnorrProof: proof,
	}, nil
}

func StartRound2(r1 *round1) (*round2, error) {
	return &round2{
		ReceivedCommitments: make(map[common.Party]*InputRound2, len(r1.Parties)-1),
		round1:              r1,
	}, nil
}

func (r2 *round2) Update(party common.Party, input *InputRound2) error {
	if stored, ok := r2.ReceivedCommitments[party]; ok && stored == nil {
		return fmt.Errorf("round2: party: %d: %w", party, ErrDuplicateInput)
	}
	if len(input.VSSCommitments) != len(r2.VSSCommitments) {
		r2.ReceivedCommitments[party] = nil
		return fmt.Errorf("round2: party: %d: vss: wrong number of commitment: %w", party, ErrInvalidVSS)
	}

	if !input.SchnorrProof.Verify(input.VSSCommitments[0], party, params) {
		r2.ReceivedCommitments[party] = nil
		return fmt.Errorf("round2: party: %d: schnorr: %w", party, ErrInvalidSchnorr)
	}

	r2.ReceivedCommitments[party] = input

	return nil
}

func StartRound3(r2 *round2) (*round3, error) {
	if len(r2.ReceivedCommitments) != len(r2.Parties)-1 {
		return nil, fmt.Errorf("round3: start: %w", ErrMissingValues)
	}
	for party, inputs := range r2.ReceivedCommitments {
		if inputs == nil {
			return nil, fmt.Errorf("round3: start: party: %d: vss: %w", party, ErrInvalidVSS)
		}
	}

	return &round3{
		ReceivedShares: make(map[common.Party]*vss.Share),
		round2:         r2,
	}, nil
}

func (r3 *round3) Update(party common.Party, input *InputRound3) error {
	if stored, ok := r3.ReceivedShares[party]; ok && stored == nil {
		return fmt.Errorf("round3: party: %d: %w", party, ErrDuplicateInput)
	}

	previousVSSCommitment := r3.ReceivedCommitments[party].VSSCommitments
	if !input.Share.Verify(party, previousVSSCommitment) {
		r3.ReceivedShares[party] = nil
		return fmt.Errorf("round3: party: %d: %w", party, ErrInvalidVSS)
	}

	r3.ReceivedShares[party] = &input.Share
	return nil
}

func (r3 *round3) Finish() (*KeyGenOutput, error) {
	if len(r3.ReceivedShares) != len(r3.Parties)-1 {
		return nil, fmt.Errorf("round3: finsish: %w", ErrMissingValues)
	}
	for party, share := range r3.ReceivedShares {
		if share == nil {
			return nil, fmt.Errorf("round3: finish: party: %d: vss: %w", party, ErrInvalidVSS)
		}
	}
	allVSSCommitments := make([]vss.Commitments, 0, len(r3.Parties))
	allVSSCommitments = append(allVSSCommitments, r3.VSSCommitments)
	for _, otherCommitments := range r3.ReceivedCommitments {
		allVSSCommitments = append(allVSSCommitments, otherCommitments.VSSCommitments)
	}
	publicKeys, err := vss.GetPublicKeys(r3.Parties, allVSSCommitments)
	if err != nil {
		return nil, fmt.Errorf("round3: finsish: get public keys: %w", err)
	}

	privateKeyShare := new(big.Int)
	privateKeyShare.Add(privateKeyShare, r3.VSSShares[r3.PartyID].PrivateShare)
	for _, share := range r3.ReceivedShares {
		privateKeyShare.Add(privateKeyShare, share.PrivateShare)
	}

	return &KeyGenOutput{
		PublicKeys: publicKeys,
		PrivateKey: privateKeyShare,
	}, nil
}
