package zk

import (
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

func TestSchnorrProof(t *testing.T) {
	params := ""
	partyID := rand.Uint32()

	private := common.NewScalarRandom()
	proof, public := NewSchnorrProof(private, partyID, params)
	publicComputed := edwards25519.NewIdentityPoint().ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.True(t, proof.Verify(public, partyID, params))
}

func TestSchnorrProofFail(t *testing.T) {
	params := ""
	partyID := rand.Uint32()

	private := edwards25519.NewScalar()
	proof, public := NewSchnorrProof(private, partyID, params)
	publicComputed := edwards25519.NewIdentityPoint().ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.False(t, proof.Verify(public, partyID, params))
}
