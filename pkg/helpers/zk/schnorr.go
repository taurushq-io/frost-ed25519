package zk

import (
	"crypto/rand"
	"errors"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"
	"math/big"

	"golang.org/x/crypto/sha3"
)

var (
	ErrNonce = errors.New("failed to generate nonce for Schnorr proof")
)

type Schnorr struct {
	// commitment = v•G for random v
	commitment curve.ECPoint

	// response = v - privateInput * challenge
	response *big.Int
}

// NewSchnorr is generates a ZK proof of knowledge of privateInput.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func NewSchnorr(privateInput *big.Int, partyID common.Party, params string) (public curve.ECPoint, proof Schnorr, err error) {
	// Base point
	G := curve.NewECPointBase()

	// public = privateInput•G
	public = G.ScalarMult(privateInput.Bytes())

	// Compute commitment for random nonce
	// V = v•G
	v, err := rand.Int(rand.Reader, curve.Modulus())
	if err != nil {
		return curve.ECPoint{}, Schnorr{}, ErrNonce
	}
	V := G.ScalarMult(v.Bytes())

	// Compute challenge
	// c = H(G || V || public || partyID || params)
	h := sha3.New256()
	_, _ = h.Write(G.Bytes())
	_, _ = h.Write(V.Bytes())
	_, _ = h.Write(public.Bytes())
	_, _ = h.Write(common.BytesFromUInt32(partyID))
	_, _ = h.Write([]byte(params))

	// c = H(G | V | public | partyID | params)
	c := new(big.Int).SetBytes(h.Sum(nil))

	// Compute response
	// r = v - privateInput * c
	r := c.Mul(c, privateInput)
	r = r.Neg(r)
	r = r.Add(r, v)
	r = r.Mod(r, curve.Modulus())

	proof = Schnorr{
		commitment: V,
		response:   r,
	}

	return
}

// Schnorr.Verify verifies that the zero knowledge proof is valid.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func (proof Schnorr) Verify(public curve.ECPoint, partyID common.Party, params string) bool {
	if !public.IsOnCurve() {
		return false
	}

	G := curve.NewECPointBase()

	h := sha3.New256()
	_, _ = h.Write(G.Bytes())
	_, _ = h.Write(proof.commitment.Bytes())
	_, _ = h.Write(public.Bytes())
	_, _ = h.Write(common.BytesFromUInt32(partyID))
	_, _ = h.Write([]byte(params))

	// h = H(G | V | A | partyID | params)
	c := new(big.Int).SetBytes(h.Sum(nil))

	cA := public.ScalarMult(c.Bytes())
	rG := G.ScalarMult(proof.response.Bytes())

	// V = c • A + r • G
	V := cA.Add(rG)

	return V.Equals(proof.commitment)
}
