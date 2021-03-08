package keygen

import "github.com/taurusgroup/frost-ed25519/pkg/eddsa"

type Output struct {
	Shares    *eddsa.Shares
	SecretKey *eddsa.SecretShare
}
