package zk

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"testing"
)

func TestSchnorrProof(t *testing.T) {
	params := ""
	partyID := uint32(1)

	private := common.NewScalarRandom()
	proof, public := NewSchnorrProof(private, partyID, params)
	publicComputed := new(edwards25519.Point).ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.True(t, proof.Verify(public, partyID, params))
}

func TestSchnorrProofFail(t *testing.T) {
	params := ""
	partyID := uint32(1)

	private := edwards25519.NewScalar()
	proof, public := NewSchnorrProof(private, partyID, params)
	publicComputed := new(edwards25519.Point).ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.False(t, proof.Verify(public, partyID, params))
}
