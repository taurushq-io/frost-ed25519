package zk

import (
	"encoding/binary"
	"filippo.io/edwards25519"

	"crypto/sha512"

	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

type Schnorr struct {
	commitment *edwards25519.Point  // commitment = v•G for random v
	response   *edwards25519.Scalar // response = v - privateInput * challenge
}

func computeChallenge(generator, commitmentPublic, public *edwards25519.Point, partyID uint32, params string) *edwards25519.Scalar {

	partyIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(partyIDBytes, partyID)

	// Compute challenge
	// c = H(G || V || public || partyID || params)
	hash512 := sha512.New()
	_, _ = hash512.Write(generator.Bytes())
	_, _ = hash512.Write(commitmentPublic.Bytes())
	_, _ = hash512.Write(public.Bytes())
	_, _ = hash512.Write(partyIDBytes)
	_, _ = hash512.Write([]byte(params))

	challenge := new(edwards25519.Scalar).SetUniformBytes(hash512.Sum(nil))

	return challenge
}

// NewSchnorr is generates a ZK proof of knowledge of privateInput.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func NewSchnorrProof(private *edwards25519.Scalar, partyID uint32, params string) (proof *Schnorr, public *edwards25519.Point, err error) {
	// public = x•G
	public = new(edwards25519.Point).ScalarBaseMult(private)

	// Compute commitment for random nonce
	// V = v•G
	commitmentSecret := common.NewScalarRandom()                                 // = v
	commitmentPublic := new(edwards25519.Point).ScalarBaseMult(commitmentSecret) // V = v•G

	generator := edwards25519.NewGeneratorPoint()

	challenge := computeChallenge(generator, commitmentPublic, public, partyID, params)

	challengeMulPrivate := new(edwards25519.Scalar).Multiply(challenge, private)         // = c•private
	response := new(edwards25519.Scalar).Subtract(commitmentSecret, challengeMulPrivate) // r = v - c•private

	proof = &Schnorr{
		commitment: commitmentPublic,
		response:   response,
	}

	return proof, public, nil
}

// Schnorr.Verify verifies that the zero knowledge proof is valid.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func (proof *Schnorr) Verify(public *edwards25519.Point, partyID uint32, params string) bool {
	identity := edwards25519.NewIdentityPoint()
	// Check that the public point is not the identity
	if public.Equal(identity) == 1 {
		return false
	}
	// TODO: Check cofactor?

	generator := edwards25519.NewGeneratorPoint()

	challenge := computeChallenge(generator, proof.commitment, public, partyID, params)

	commitmentComputed := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(challenge, public, proof.response) // = r•G + c•Public

	return commitmentComputed.Equal(proof.commitment) == 1
}
