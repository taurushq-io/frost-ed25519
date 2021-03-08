package keygen

import "github.com/taurusgroup/frost-ed25519/pkg/eddsa"

type Output struct {
	Public    *eddsa.Public
	SecretKey *eddsa.SecretShare
}
