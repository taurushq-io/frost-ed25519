package zk

import (
	"crypto/elliptic"
	"github.com/stretchr/testify/require"
	common "github.com/taurusgroup/tg-tss/pkg/helpers"
	"math/big"
	"testing"
)

func TestSchnorrProof(t *testing.T) {
	common.SetCurve(elliptic.P256())
	private := new(big.Int).SetInt64(4242424242424)
	public, proof, err := NewZKSchnorr(private,1,"test")
	require.NoError(t, err)
	public_comp := common.NewECPointBaseMult(private.Bytes())
	require.True(t, public_comp.Equals(public))
	require.True(t, CheckZKSchnorr(public, proof))
}

func TestSchnorrProofFail(t *testing.T) {
	common.SetCurve(elliptic.P256())
	private := new(big.Int)
	public, proof, err := NewZKSchnorr(private,1,"test")
	require.NoError(t, err)
	public_comp := common.NewECPointBaseMult(private.Bytes())
	require.True(t, public_comp.Equals(public))
	require.False(t, CheckZKSchnorr(public, proof))
}