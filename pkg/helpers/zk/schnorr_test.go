package zk

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

func TestSchnorrProof(t *testing.T) {
	params := ""
	partyID := common.Party(1)

	private, err := common.NewScalarRandom()
	require.NoError(t, err, "failed to generate random private scalar")
	proof, public, err := NewSchnorrProof(private, partyID, params)
	require.NoError(t, err, "proof generation failed")
	publicComputed := new(edwards25519.Point).ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.True(t, proof.Verify(public, partyID, params))
}

func TestSchnorrProofFail(t *testing.T) {
	params := ""
	partyID := common.Party(1)

	private := edwards25519.NewScalar()
	proof, public, err := NewSchnorrProof(private, partyID, params)
	require.NoError(t, err, "proof generation failed")
	publicComputed := new(edwards25519.Point).ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.False(t, proof.Verify(public, partyID, params))
}
