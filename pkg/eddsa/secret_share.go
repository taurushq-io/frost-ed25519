package eddsa

import (
	"encoding/json"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// SecretShare is a share of a secret key computed during the KeyGen protocol.
type SecretShare struct {
	// ID of the party this SecretShare belongs to
	ID party.ID

	// Secret is the Shamir share of the group's secret key
	Secret ristretto.Scalar

	// Public is the Shamir share of the group's public key
	Public ristretto.Element
}

// NewSecretShare returns a SecretShare given a party.ID and ristretto.Scalar
func NewSecretShare(id party.ID, secret *ristretto.Scalar) *SecretShare {
	var share SecretShare
	share.ID = id
	share.Secret.Set(secret)
	share.Public.ScalarBaseMult(secret)
	return &share
}

// sign generates an Ed25519 compatible signature for the message.
func (sk *SecretShare) sign(message []byte) *Signature {
	var sig Signature

	// R = [r] • B
	r := scalar.NewScalarRandom()
	sig.R.ScalarBaseMult(r)

	pk := PublicKey{pk: sk.Public}

	// C = H(R, A, M)
	c := ComputeChallenge(&sig.R, &pk, message)

	// S = Secret * c + r
	sig.S.MultiplyAdd(&sk.Secret, c, r)
	return &sig
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (sk *SecretShare) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0, party.ByteSize+32)
	data = append(data, sk.ID.Bytes()...)
	data = append(data, sk.Secret.Bytes()...)
	return data, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (sk *SecretShare) UnmarshalBinary(data []byte) error {
	if len(data) != party.ByteSize+32 {
		return errors.New("SecretShare: data is not the right size")
	}
	sk.ID = party.FromBytes(data)
	data = data[party.ByteSize:]
	_, err := sk.Secret.SetCanonicalBytes(data)
	if err != nil {
		return err
	}
	sk.Public.ScalarBaseMult(&sk.Secret)
	return nil
}

type jsonSecretShare struct {
	ID          int    `json:"id"`
	SecretShare []byte `json:"secret"`
}

// MarshalJSON implements the json.Marshaler interface.
func (sk *SecretShare) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSecretShare{
		ID:          int(sk.ID),
		SecretShare: sk.Secret.Bytes(),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (sk *SecretShare) UnmarshalJSON(data []byte) error {
	var out jsonSecretShare
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	sk.ID = party.ID(out.ID)
	if _, err := sk.Secret.SetCanonicalBytes(out.SecretShare); err != nil {
		return err
	}
	sk.Public.ScalarBaseMult(&sk.Secret)
	return nil
}

func (sk *SecretShare) Equal(sk2 *SecretShare) bool {
	if sk.ID != sk2.ID {
		return false
	}
	return sk.Secret.Equal(&sk2.Secret) == 1
}
