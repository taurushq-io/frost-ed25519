package scalar

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScalarUInt32(t *testing.T) {
	b := make([]byte, 32)
	b[0] = byte(1)

	one, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	require.NoError(t, err, "create 1")

	tests := []uint32{1, 2, 200, 499, 1025}

	for _, test := range tests {
		computed := NewScalarUInt32(test)
		newScalar := edwards25519.NewScalar()
		for i := uint32(0); i < test; i++ {
			newScalar.Add(newScalar, one)
		}
		assert.Equal(t, 1, computed.Equal(newScalar))
	}
}
