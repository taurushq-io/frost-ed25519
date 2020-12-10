package zk

import (
	"errors"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/curve"

	"golang.org/x/crypto/sha3"
)

var (
	ErrNonce = errors.New("failed to generate nonce for Schnorr proof")
)

type Schnorr struct {
	curve curve.Curve
	// commitment = v•G for random v
	commitment curve.Point
	// response = v - privateInput * challenge
	response curve.Scalar
}



// NewSchnorr is generates a ZK proof of knowledge of privateInput.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func NewSchnorrProof(curve curve.Curve, private curve.Scalar, id common.Party, params string) (proof *Schnorr, public curve.Point, err error) {
	// public = x•G
	public = curve.Point().ScalarBaseMult(private)


	// Compute commitment for random nonce
	// V = v•G
	v, err := curve.Scalar().Rand()
	if err != nil {
		return nil, nil, err
	}
	V := curve.Point().ScalarBaseMult(v)

	// Compute challenge
	// c = H(G || V || public || partyID || params)
	h := sha3.New256()
	_, _ = h.Write(curve.Point().Base().Encode(nil))
	_, _ = h.Write(V.Encode(nil))
	_, _ = h.Write(public.Encode(nil))
	_, _ = h.Write(common.BytesFromUInt32(id))
	_, _ = h.Write([]byte(params))


	// c = H(G | V | public | partyID | params)
	c, err := curve.Scalar().Decode(h.Sum(nil))
	if err != nil {
		return nil, nil, err
	}

	// Compute response
	r := curve.Scalar().Set(c)	// r = c
	r.Multiply(r, private)		// r = c * private
	r.Negate(r)					// r = - c * private
	r.Add(r, v)					// r = v - c * private

	proof = &Schnorr{
		curve:      curve,
		commitment: V,
		response:   r,
	}

	return proof, public, nil
}

// Schnorr.Verify verifies that the zero knowledge proof is valid.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func (proof Schnorr) Verify(public curve.Point, partyID common.Party, params string) bool {
	// Check that the public point is not ∞
	if public.Equal(proof.curve.Point().Infinity()) == 1 {
		return false
	}

	G := proof.curve.Point().Base()

	// Compute challenge
	// c = H(G || V || public || partyID || params)
	h := sha3.New256()
	_, _ = h.Write(G.Encode(nil))
	_, _ = h.Write(proof.commitment.Encode(nil))
	_, _ = h.Write(public.Encode(nil))
	_, _ = h.Write(common.BytesFromUInt32(partyID))
	_, _ = h.Write([]byte(params))

	// c = H(G | V | public | partyID | params)
	c, err := proof.curve.Scalar().Decode(h.Sum(nil))
	if err != nil {
		return false
	}


	V2 := proof.curve.Point().ScalarBaseMult(proof.response)	// V = r•G
	V2.Add(V2, proof.curve.Point().ScalarMult(c, public))		// V = r•G + c•public

	return V2.Equal(proof.commitment) == 1
}
