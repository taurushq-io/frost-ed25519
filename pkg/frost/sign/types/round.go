package types

import (
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type ProtocolVersion int

const (
	FROST_1 ProtocolVersion = iota
	FROST_2
)

type FrostRound struct {
	*state.BaseRound

	Version ProtocolVersion

	// Message is the message to be signed
	Message []byte

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

func (round *FrostRound) Reset() {
	zero := ristretto.NewScalar()
	one := ristretto.NewIdentityElement()

	round.Message = nil

	round.C.Set(zero)
	round.R.Set(one)

	round.Output = nil
}
