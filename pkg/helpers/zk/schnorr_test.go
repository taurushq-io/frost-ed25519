package zk

import (
	"fmt"
	"testing"

	"filippo.io/edwards25519"
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

func TestSchnorrProofFail(t *testing.T) {
	partyID := uint32(42)

	secret := edwards25519.NewScalar()
	public := new(edwards25519.Point).ScalarBaseMult(secret)

	ctx := make([]byte, 32)
	proof := NewSchnorrProof(partyID, public, ctx, secret)
	data, _ := proof.MarshalBinary()
	var proof2 Schnorr
	proof2.UnmarshalBinary(data)

	require.False(t, proof2.Verify(partyID, public, ctx))
}

func TestSchnorrCofactor(t *testing.T) {
	partyID := uint32(42)

	secret := edwards25519.NewScalar()
	public := new(edwards25519.Point).ScalarBaseMult(secret)

	ctx := make([]byte, 32)
	proof := NewSchnorrProof(partyID, public, ctx, secret)
	data, _ := proof.MarshalBinary()
	var proof2 Schnorr
	proof2.UnmarshalBinary(data)
	fmt.Println(1, proof.S.Bytes(), proof.R.Bytes())
	fmt.Println(2, proof2.S.Bytes(), proof2.R.Bytes())
	require.False(t, proof2.Verify(partyID, public, ctx))
}
