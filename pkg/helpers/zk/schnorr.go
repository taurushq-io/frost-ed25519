package zk

import (
	"crypto/rand"
	"fmt"
	common "github.com/taurusgroup/tg-tss/pkg/helpers"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type ZKSchnorr struct {
	partyID int
	params string
	commitment *common.ECPoint
	response *big.Int
}

// NewZKSchnorr is generates a ZK proof of knowledge of privateInput.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func NewZKSchnorr(privateInput *big.Int, partyID int, params string) (*common.ECPoint, ZKSchnorr, error) {
	v, err := rand.Int(rand.Reader, common.Modulus())
	if err != nil {
		return nil, ZKSchnorr{}, fmt.Errorf("failed to generate random nonce for schnorr proof")
	}
	G := common.NewECPointBase()
	V := G.ScalarMult(v.Bytes())
	A := G.ScalarMult(privateInput.Bytes())

	// H(G | V | A | partyID | params)
	h := sha3.New256()
	h.Write(G.Bytes())
	h.Write(V.Bytes())
	h.Write(A.Bytes())
	h.Write(common.IntToBytes(partyID))
	h.Write([]byte(params))
	// h = H(G | V | A | partyID | params)
	c := new(big.Int).SetBytes(h.Sum(nil))

	// r = v - privateInput * c
	r := c.Mul(c, privateInput)
	r = r.Neg(r)
	r = r.Add(r, v)
	r = r.Mod(r, common.Modulus())

	proof := ZKSchnorr{
		partyID:   partyID,
		params:    params,
		commitment: V,
		response:  r,
	}
	return A, proof, nil
}

func CheckZKSchnorr(public *common.ECPoint, proof ZKSchnorr) bool {
	if !public.IsOnCurve() {
		return false
	}

	G := common.NewECPointBase()

	h := sha3.New256()
	h.Write(G.Bytes())
	h.Write(proof.commitment.Bytes())
	h.Write(public.Bytes())
	h.Write(common.IntToBytes(proof.partyID))
	h.Write([]byte(proof.params))
	// h = H(G | V | A | partyID | params)
	c := new(big.Int).SetBytes(h.Sum(nil))


	Ac := public.ScalarMult(c.Bytes())
	Gr := common.NewECPointBaseMult(proof.response.Bytes())

	V := Ac.Add(Gr)
	return V.Equals(proof.commitment)
}