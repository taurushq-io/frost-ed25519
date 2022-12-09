package signer

import (
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign/types"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

type (
	Round0Signer struct {
		*types.FrostRound
		SecretKeyShare ristretto.Scalar

		// e and d are the scalars committed to in the first round
		e, d ristretto.Scalar
	}
	Round1Signer struct {
		*Round0Signer
	}
	Round2Signer struct {
		*Round0Signer
	}
)

func (round *Round0Signer) Reset() {
	round.FrostRound.Reset()

	zero := ristretto.NewScalar()

	round.SecretKeyShare.Set(zero)

	round.e.Set(zero)
	round.d.Set(zero)
}

func (round *Round0Signer) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{
		messages.MessageTypeNone,
		messages.MessageTypeSign1,
		messages.MessageTypeSign2,
	}
}