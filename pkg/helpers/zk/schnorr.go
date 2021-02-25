package zk

import (
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"

	"crypto/sha512"

	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

type Schnorr struct {
	commitment edwards25519.Point  // commitment = v•G for random v
	response   edwards25519.Scalar // response = v - privateInput * challenge
}

var edwards25519GeneratorBytes = edwards25519.NewGeneratorPoint().Bytes()

func computeChallenge(commitmentPublic, public *edwards25519.Point, partyID uint32) *edwards25519.Scalar {
	var challenge edwards25519.Scalar
	// c = H(G || V || public || partyID)

	hashBuffer := make([]byte, 0, 32+32+32+4)
	hashBuffer = append(hashBuffer, edwards25519GeneratorBytes...)
	hashBuffer = append(hashBuffer, commitmentPublic.Bytes()...)
	hashBuffer = append(hashBuffer, public.Bytes()...)
	binary.BigEndian.PutUint32(hashBuffer, partyID)

	digest := sha512.Sum512(hashBuffer)
	challenge.SetUniformBytes(digest[:])

	return &challenge
}

// NewSchnorrProof is generates a ZK proof of knowledge of privateInput.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func NewSchnorrProof(private *edwards25519.Scalar, partyID uint32, params string) (*Schnorr, *edwards25519.Point) {
	var public edwards25519.Point
	var proof Schnorr

	// public = x•G
	public.ScalarBaseMult(private)

	// Compute commitment for random nonce
	// V = v•G
	commitmentSecret := scalar.NewScalarRandom()      // = v
	proof.commitment.ScalarBaseMult(commitmentSecret) // V = v•G

	challenge := computeChallenge(&proof.commitment, &public, partyID)

	proof.response.Multiply(challenge, private)                // = c•private
	proof.response.Subtract(commitmentSecret, &proof.response) // r = v - c•private

	return &proof, &public
}

// Schnorr.Verify verifies that the zero knowledge proof is valid.
// Follows https://tools.ietf.org/html/rfc8235#section-3
func (proof *Schnorr) Verify(public *edwards25519.Point, partyID uint32, params string) bool {
	var commitmentComputed edwards25519.Point

	// Check that the public point is not the identity
	if public.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	// TODO: Check cofactor?

	challenge := computeChallenge(&proof.commitment, public, partyID)

	commitmentComputed.VarTimeDoubleScalarBaseMult(challenge, public, &proof.response) // = r•G + c•Public

	return commitmentComputed.Equal(&proof.commitment) == 1
}

//
// FROSTMarshaller
//

func (proof *Schnorr) MarshalBinary() (data []byte, err error) {
	var buf [64]byte
	return proof.BytesAppend(buf[:0])
}

func (proof *Schnorr) UnmarshalBinary(data []byte) error {
	if len(data) != 64 {
		return errors.New("length is wrong")
	}
	var err error
	_, err = proof.commitment.SetBytes(data[:32])
	if err != nil {
		return err
	}
	_, err = proof.response.SetCanonicalBytes(data[32:])
	if err != nil {
		return err
	}
	return nil
}

func (proof *Schnorr) BytesAppend(existing []byte) (data []byte, err error) {
	existing = append(existing, proof.commitment.Bytes()...)
	existing = append(existing, proof.response.Bytes()...)
	return existing, nil
}

func (proof *Schnorr) Size() int {
	return 64
}

func (proof *Schnorr) Equal(other interface{}) bool {
	otherProof, ok := other.(*Schnorr)
	if !ok {
		return false
	}
	if otherProof.commitment.Equal(&proof.commitment) != 1 {
		return false
	}
	if otherProof.response.Equal(&proof.response) != 1 {
		return false
	}
	return true
}
