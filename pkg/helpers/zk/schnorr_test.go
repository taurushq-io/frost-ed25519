package zk

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func TestSchnorrProof(t *testing.T) {
	partyID := uint32(42)
	private := scalar.NewScalarRandom()
	public := new(edwards25519.Point).ScalarBaseMult(private)
	ctx := make([]byte, 32)
	proof := NewSchnorrProof(partyID, public, ctx, private)
	publicComputed := edwards25519.NewIdentityPoint().ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.True(t, proof.Verify(partyID, public, ctx))
}

func TestSchnorrCofactor(t *testing.T) {
	partyID := uint32(42)

	secret := edwards25519.NewScalar()
	public := new(edwards25519.Point).ScalarBaseMult(secret)

	ctx := make([]byte, 32)
	proof := NewSchnorrProof(partyID, public, ctx, secret)

	for i, T := range order8 {
		var publicPrime edwards25519.Point
		// TODO This should not work
		if T.Equal(edwards25519.NewIdentityPoint()) != 1 {
			assert.False(t, proof.Verify(partyID, publicPrime.Add(public, T), ctx), i)
		}
	}
}

var order8 []*edwards25519.Point

func init() {
	order8Hex := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A",
		"C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA",
		"26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05",
		"26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85",
	}
	order8 = make([]*edwards25519.Point, 0, 8)
	for _, h := range order8Hex {
		b, _ := hex.DecodeString(h)
		p, _ := new(edwards25519.Point).SetBytes(b)
		order8 = append(order8, p)
	}
}
