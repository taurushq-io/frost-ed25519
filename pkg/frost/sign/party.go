package sign

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/frost"
)

type Signer struct {
	frost.Party

	// Di = [di]•B
	// Ei = [ei]•B
	Di, Ei edwards25519.Point

	// Ri = Di + [ρ] Ei
	Ri edwards25519.Point

	// Pi = ρ = H(i, Message, B)
	Pi edwards25519.Scalar

	// Zi = z = d + (e • ρ) + 𝛌 • s • c
	Zi edwards25519.Scalar
}

func NewSigner(p *frost.Party) *Signer {
	var s Signer
	s.Party = *p
	return &s
}
