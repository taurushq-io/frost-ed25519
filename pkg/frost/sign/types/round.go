package types

import (
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type ProtocolVersion int

type FrostRound struct {
	// Message is the message to be signed
	Message []byte

	// Parties maps IDs to a struct containing all intermediary data for each signer.
	Parties map[party.ID]*Signer

	// C = H(R, GroupKey, Message)
	C ristretto.Scalar
	// R = ∑ Ri
	R ristretto.Element
	// if the protocol version is FROST2
	// P = ρ = H(Message, B)
	// This does means there is one global shift for the nonces instead of one for each signer
	// This allows for 1 group exponentiation instead of t
	P ristretto.Scalar

	// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
	GroupKey eddsa.PublicKey

	Output *Output
}

func (round *FrostRound) Reset() {
	zero := ristretto.NewScalar()
	one := ristretto.NewIdentityElement()

	round.Message = nil

	round.C.Set(zero)
	round.R.Set(one)

	round.Output = nil
}
