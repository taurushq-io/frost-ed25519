package polynomial

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestLagrangeCoefficient(t *testing.T) {
	one := LagrangeCoefficient(0, nil)
	g := edwards25519.NewIdentityPoint().ScalarBaseMult(one)
	assert.Equal(t, 1, g.Equal(edwards25519.NewGeneratorPoint()))

	s := scalar.NewScalarRandom()
	p := edwards25519.NewIdentityPoint().ScalarBaseMult(s)
	p2 := edwards25519.NewIdentityPoint().ScalarMult(one, p)
	assert.Equal(t, 1, p.Equal(p2))
}
