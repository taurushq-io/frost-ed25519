package common

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewScalarUInt32(t *testing.T) {
	b := make([]byte, 32)
	b[0] = byte(1)

	one, err := new(edwards25519.Scalar).SetCanonicalBytes(b)
	require.NoError(t, err, "create 1")

	tests := []uint32{1, 2, 200,499, 1025}

	for _, test := range tests {
		computed, err := NewScalarUInt32(test)
		require.NoError(t, err, "create", test)
		real := edwards25519.NewScalar()
		for i := uint32(0); i<test; i++ {
			real.Add(real, one)
		}
		require.Equal(t, 1, computed.Equal(real))
	}
}
