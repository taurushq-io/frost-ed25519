package vss

import (
	"crypto/elliptic"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"
	"math/big"
	"testing"
)

var constantInt = new(big.Int).SetInt64(42)
var zeroInt = new(big.Int)

func TestPolynomialEvalZero(t *testing.T) {
	curve.SetCurve(elliptic.P256())
	p := Polynomial{}
	result1 := p.Evaluate(zeroInt)
	result2 := p.Evaluate(constantInt)
	require.True(t, result1.Cmp(zeroInt) == 0)
	require.True(t, result2.Cmp(zeroInt) == 0)
}

func TestPolynomialEvalConst(t *testing.T) {
	curve.SetCurve(elliptic.P256())
	p, err := NewRandomPolynomial(0, constantInt)
	require.NoError(t, err)
	require.True(t, len(p) == 1)
	require.True(t, p[0].Cmp(constantInt) == 0)
	result1 := p.Evaluate(zeroInt)
	result2 := p.Evaluate(constantInt)
	require.True(t, result1.Cmp(constantInt) == 0)
	require.True(t, result2.Cmp(constantInt) == 0)
}

func TestNewRandomPolynomial(t *testing.T) {
	curve.SetCurve(elliptic.P256())
	p, err := NewRandomPolynomial(0, constantInt)
	require.NoError(t, err)
	require.True(t, len(p) == 1)
	require.True(t, p[0].Cmp(constantInt) == 0)
}
