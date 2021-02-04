package frost

import (
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/vss"
	"github.com/taurusgroup/tg-tss/pkg/helpers/zk"
)

var params = ""

var (
	ErrInvalidSchnorr = errors.New("invalid Schnorr proof")
	ErrMissingValues  = errors.New("missing inputs")
	ErrDuplicateInput = errors.New("already received input")
	ErrInvalidVSS     = errors.New("bad VSS input")
	ErrPartyNotValid  = errors.New("party is not valid")
)

type (
	KeyGenParameters struct {
		OtherPartyIDs []common.Party
		SelfPartyID   common.Party
		Threshold     uint32
	}

	KeyGenRound1 struct {
		*KeyGenParameters
	}
	KeyGenMessage1 struct {
		VSS   *vss.VSS
		Proof *zk.Schnorr
	}

	KeyGenRound2 struct {
		*KeyGenRound1

		VSSs                           map[common.Party]*vss.VSS
		ReceivedShares, OutgoingShares vss.Shares
	}
	KeyGenMessage2 struct {
		Share *edwards25519.Scalar
	}

	KeyGenRoundFinal struct {
		*KeyGenRound2
		PublicKey  *edwards25519.Point
		PublicKeys map[common.Party]*edwards25519.Point
		PrivateKey *edwards25519.Scalar
	}
)

func (params *KeyGenParameters) AllPartyIDs() []common.Party {
	return append(params.OtherPartyIDs, params.SelfPartyID)
}

func (params *KeyGenParameters) PartyCount() uint32 {
	return uint32(len(params.OtherPartyIDs) + 1)
}

func (r *KeyGenRound1) GetMessagesOut() (messages *Message, round *KeyGenRound2, err error) {
	secret, err := common.NewScalarRandom()
	if err != nil {
		return nil, nil, err
	}
	commitments, shares, err := vss.NewVSS(r.Threshold, secret, r.AllPartyIDs())
	if err != nil {
		return nil, nil, err
	}
	proof, _, err := zk.NewSchnorrProof(secret, r.SelfPartyID, "")
	if err != nil {
		return nil, nil, err
	}

	messages = &Message{
		KeyGen: &KeyGenMessage{
			Message1: &KeyGenMessage1{
				VSS:   commitments,
				Proof: proof,
			},
		},
	}
	round = &KeyGenRound2{
		KeyGenRound1:   r,
		VSSs:           map[common.Party]*vss.VSS{r.SelfPartyID: commitments},
		ReceivedShares: vss.Shares{r.SelfPartyID: shares[r.SelfPartyID]},
		OutgoingShares: shares,
	}
	return
}

func (r *KeyGenRound2) ProcessMessage(from common.Party, msg *Message) error {
	found := false
	for _, otherParty := range r.OtherPartyIDs {
		found = found || (otherParty == from)
	}
	if !found {
		return ErrPartyNotValid
	}
	if msg == nil || msg.KeyGen == nil || msg.KeyGen.Message1 == nil {
		return ErrMissingValues
	}

	msg1 := msg.KeyGen.Message1

	public := msg1.VSS.PublicKey()

	if !msg1.Proof.Verify(public, from, "") {
		return ErrInvalidSchnorr
	}

	if !msg1.VSS.Verify(r.Threshold, r.PartyCount()) {
		return ErrInvalidVSS
	}

	r.VSSs[from] = msg1.VSS

	return nil
}

func (r *KeyGenRoundFinal) ProcessMessage(from common.Party, msg *Message) error {
	found := false
	for _, otherParty := range r.OtherPartyIDs {
		found = found || (otherParty == from)
	}
	if !found {
		return ErrPartyNotValid
	}

	if msg == nil || msg.KeyGen == nil || msg.KeyGen.Message2 == nil {
		return ErrMissingValues
	}

	msg2 := msg.KeyGen.Message2

	r.ReceivedShares[from] = msg2.Share

	return nil
}

func (r *KeyGenRoundFinal) Finish() {
	combinedVSS, err := vss.SumVSS(r.VSSs, r.Threshold, r.PartyCount())
	if err != nil {
		panic(err)
	}

	r.PrivateKey = edwards25519.NewScalar()
	r.PublicKey = combinedVSS.PublicKey()

	r.PublicKeys = combinedVSS.PublicKeys(r.AllPartyIDs())

	for _, partyID := range r.AllPartyIDs() {
		r.PrivateKey.Add(r.PrivateKey, r.ReceivedShares[partyID])
	}
}
