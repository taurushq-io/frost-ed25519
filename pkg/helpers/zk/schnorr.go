package zk

import (
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"

	"crypto/sha512"

	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

// Schnorr is a Non-Interactive Zero-Knowledge proof of knowledge of
// the discrete logarithm of public = [secret] B
//
// The public parameters are:
//   partyID: prover's uint32 ID
//   context: 32 byte context string,
//   public:  [secret] B
//
type Schnorr struct {
	// S = H( ID || CTX || public || M )
	// R = k + secret • s
	S, R edwards25519.Scalar
}

// challenge computes the hash H(partyID, context, public, M), where
//   partyID: prover's uint32 ID
//   context: 32 byte context string,
//   public:  [secret] B
//   M:       [k] B
func challenge(partyID uint32, context []byte, public, M *edwards25519.Point) *edwards25519.Scalar {
	// S = H( ID || CTX || Public || M )
	var S edwards25519.Scalar

	hashBuffer := make([]byte, 4, 4+32+32+32)
	binary.BigEndian.PutUint32(hashBuffer, partyID)
	hashBuffer = append(hashBuffer, context[:32]...)
	hashBuffer = append(hashBuffer, public.Bytes()...)
	hashBuffer = append(hashBuffer, M.Bytes()...)

	digest := sha512.Sum512(hashBuffer)
	S.SetUniformBytes(digest[:])

	return &S
}

// NewSchnorrProof computes a NIZK proof of knowledge of discrete.
//    partyID is the uint32 ID of the prover
//    public is the point [private]•B
//    context is a 32 byte context (if it is set to [0 ... 0] then we may be susceptible to replay attacks)
//    private is the discrete log of public
//
// We sample a random Scalar k, and obtain M = [k]•B
// S := H(ID,CTX,Public,M)
// R := k + private•S
//
// The proof returned is the tuple (S,R)
func NewSchnorrProof(partyID uint32, public *edwards25519.Point, context []byte, private *edwards25519.Scalar) *Schnorr {
	var (
		proof Schnorr
		M     edwards25519.Point
	)

	// Compute commitment for random nonce
	k := scalar.NewScalarRandom()
	// M = [k] B
	M.ScalarBaseMult(k)

	S := challenge(partyID, context, public, &M)
	proof.S.Set(S)
	proof.R.MultiplyAdd(private, S, k)

	return &proof
}

// Verify verifies that the zero knowledge proof is valid.
//    partyID is the uint32 ID of the prover
//    public is the point [private]•B
//    context is a 32 byte context (if it is set to [0 ... 0] then we may be susceptible to replay attacks)
func (proof *Schnorr) Verify(partyID uint32, public *edwards25519.Point, context []byte) bool {
	var MPrime, publicNeg edwards25519.Point

	publicNeg.Negate(public)

	MPrime.VarTimeDoubleScalarBaseMult(&proof.S, &publicNeg, &proof.R)

	SPrime := challenge(partyID, context, public, &MPrime)

	return proof.S.Equal(SPrime) == 1
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
	//proof.S.SetBytesWithClamping(data[:32])
	//proof.R.SetBytesWithClamping(data[32:])
	var err error
	_, err = proof.S.SetCanonicalBytes(data[:32])
	if err != nil {
		return err
	}
	_, err = proof.R.SetCanonicalBytes(data[32:])
	if err != nil {
		return err
	}
	return nil
}

func (proof *Schnorr) BytesAppend(existing []byte) (data []byte, err error) {
	existing = append(existing, proof.S.Bytes()...)
	existing = append(existing, proof.R.Bytes()...)
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
	if otherProof.S.Equal(&proof.S) != 1 {
		return false
	}
	if otherProof.R.Equal(&proof.R) != 1 {
		return false
	}
	return true
}
