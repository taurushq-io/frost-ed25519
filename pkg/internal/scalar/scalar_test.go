package scalar

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestNewScalarUInt32(t *testing.T) {
	b := make([]byte, 32)
	b[0] = byte(1)

	one, err := ristretto.NewScalar().SetCanonicalBytes(b)
	require.NoError(t, err, "create 1")

	tests := []uint32{1, 2, 200, 499, 1025}

	for _, test := range tests {
		computed := NewScalarUInt32(test)
		newScalar := ristretto.NewScalar()
		for i := uint32(0); i < test; i++ {
			newScalar.Add(newScalar, one)
		}
		assert.Equal(t, 1, computed.Equal(newScalar))
	}
}
