package common

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewScalarUInt32(t *testing.T) {
	b := make([]byte, 32)
	b[0] = byte(1)

	one, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	require.NoError(t, err, "create 1")

	tests := []uint32{1, 2, 200, 499, 1025}

	for _, test := range tests {
		//if test == 200 {
		//	a := big.NewInt(1 << 12 + 1 << 30)
		//	ab := a.Bytes()
		//	c, _ := NewScalarUInt32(1 << 12 + 1 << 30)
		//	print(a, c, ab)
		//}
		computed := NewScalarUInt32(test)
		newScalar := edwards25519.NewScalar()
		for i := uint32(0); i < test; i++ {
			newScalar.Add(newScalar, one)
		}
		require.Equal(t, 1, computed.Equal(newScalar))
	}
}
