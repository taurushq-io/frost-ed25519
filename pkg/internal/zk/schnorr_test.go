package zk

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestSchnorrProof(t *testing.T) {
	var ctx [32]byte
	partyID := party.ID(42)
	private := scalar.NewScalarRandom()
	public := new(ristretto.Element).ScalarBaseMult(private)
	proof := NewSchnorrProof(partyID, public, ctx[:], private)
	publicComputed := ristretto.NewIdentityElement().ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.True(t, proof.Verify(partyID, public, ctx[:]))
	require.False(t, proof.Verify(partyID+1, public, ctx[:]))
	ctx[0] = 1
	require.False(t, proof.Verify(partyID, public, ctx[:]))
	ctx[0] = 0
	require.False(t, proof.Verify(partyID, ristretto.NewIdentityElement().Negate(public), ctx[:]))
}
