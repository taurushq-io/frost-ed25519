package messages

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
)

type KeyGenOutput struct {
	GroupKey     eddsa.PublicKey
	PublicShares map[uint32]*eddsa.PublicKey
	SecretShare  edwards25519.Scalar
}

func NewKeyGenOutput(ID uint32, GroupKey *eddsa.PublicKey, PublicShares map[uint32]*eddsa.PublicKey, secretKey *edwards25519.Scalar) *Message {
	return &Message{
		Type: MessageTypeKeyGenOutput,
		To:   ID,
		KeyGenOutput: &KeyGenOutput{
			GroupKey:     *GroupKey,
			PublicShares: PublicShares,
			SecretShare:  *secretKey,
		},
	}
}
