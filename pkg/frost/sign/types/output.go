package types

import "github.com/taurusgroup/frost-ed25519/pkg/eddsa"

type Output struct {
	Signature *eddsa.Signature
}
