package sign

import (
	"filippo.io/edwards25519"
	"testing"
)

func TestSigner_Reset(t *testing.T) {
	a := new(Signer)
	z := edwards25519.NewIdentityPoint()
	a.R.Set(z)
}
