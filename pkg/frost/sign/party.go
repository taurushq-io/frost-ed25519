package sign

import (
	"filippo.io/edwards25519"
)

// A signer represents the state we store for one particular
// co-signer. It can safely be reset once a signature has
// been generated, or an abort was detected.
type signer struct {
	// signer's additive share of the Public key.
	// It is multiplied by the party's Lagrange coefficient
	// so the we do need to do so later.
	Public edwards25519.Point

	// Di = [di]•B
	// Ei = [ei]•B
	// These are the commitments which can be
	// preprocessed
	Di, Ei edwards25519.Point

	// Ri = Di + [ρ] Ei
	// This is a share of the nonce R
	Ri edwards25519.Point

	// Pi = ρ = H(i, Message, B)
	// This is the 'rho' from the paper
	Pi edwards25519.Scalar

	// Zi = z = d + (e • ρ) + 𝛌 • s • c
	// This is the share of the final signature
	Zi edwards25519.Scalar
}

// Reset sets all values to default.
// The party is no longer usable since the public key is deleted.
func (signer *signer) Reset() {
	zero := edwards25519.NewScalar()
	identity := edwards25519.NewIdentityPoint()

	signer.Public.Set(identity)
	signer.Ei.Set(identity)
	signer.Di.Set(identity)
	signer.Ri.Set(identity)

	signer.Pi.Set(zero)
	signer.Zi.Set(zero)
}