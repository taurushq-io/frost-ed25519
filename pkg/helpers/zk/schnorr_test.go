package zk

import (
	"crypto/elliptic"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"
	"math/big"
	"testing"
)

func TestSchnorrProof(t *testing.T) {
	curve.SetCurve(elliptic.P256())
	params := ""
	partyID := common.Party(1)

	private := new(big.Int).SetInt64(4242424242424)
	public, proof, err := NewSchnorr(private, partyID, params)
	require.NoError(t, err)
	public_comp := curve.NewECPointBaseMult(private.Bytes())
	require.True(t, public_comp.Equals(public))
	require.True(t, proof.Verify(public, partyID, params))
}

func TestSchnorrProofFail(t *testing.T) {
	curve.SetCurve(elliptic.P256())
	params := ""
	partyID := common.Party(1)

	private := new(big.Int)
	public, proof, err := NewSchnorr(private, partyID, params)
	require.NoError(t, err)
	public_comp := curve.NewECPointBaseMult(private.Bytes())
	require.True(t, public_comp.Equals(public))
	require.False(t, proof.Verify(public, partyID, params))
}
