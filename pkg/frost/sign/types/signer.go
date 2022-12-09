package types

import (
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// A signer represents the state we store for one particular
// co-signer. It can safely be reset once a signature has
// been generated, or an abort was detected.
type Signer struct {
	// signer's additive share of the Public key.
	// It is multiplied by the party's Lagrange coefficient
	// so the we do need to do so later.
	Public ristretto.Element

	// Di = [di]•B
	// Ei = [ei]•B
	Di, Ei ristretto.Element

	// Ri = Di + [ρ] Ei
	// This is a share of the nonce R
	Ri ristretto.Element

	// Pi = ρ = H(i, Message, B)
	// This is the 'rho' from the paper
	Pi ristretto.Scalar

	// Zi = z = d + (e • ρ) + 𝛌 • s • c
	// This is the share of the final signature
	Zi ristretto.Scalar
}

// Reset sets all values to default.
// The party is no longer usable since the public key is deleted.
func (signer *Signer) Reset() {
	zero := ristretto.NewScalar()
	identity := ristretto.NewIdentityElement()

	signer.Ei.Set(identity)
	signer.Di.Set(identity)

	signer.Ri.Set(identity)

	signer.Pi.Set(zero)
	signer.Zi.Set(zero)
}
