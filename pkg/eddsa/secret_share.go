package eddsa

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

// SecretShare is a share of a secret key computed during the KeyGen protocol.
type SecretShare struct {
	ID party.ID
	sk edwards25519.Scalar
}

// NewSecretShare returns a SecretShare given a party.ID and  edwards25519.Scalar
func NewSecretShare(id party.ID, secret *edwards25519.Scalar) *SecretShare {
	var share SecretShare
	share.ID = id
	share.sk.Set(secret)
	return &share
}

// Scalar returns a reference to the edwards25519.Scalar representing the private key.
func (sk *SecretShare) Scalar() *edwards25519.Scalar {
	return &sk.sk
}

// PublicKey returns a reference to the edwards25519.Scalar representing the private key.
func (sk *SecretShare) PublicKey() *PublicKey {
	var pk PublicKey
	pk.pk.ScalarBaseMult(&sk.sk)
	return &pk
}

// MarshalBinary implements the BinaryMarshaler interface.
func (sk *SecretShare) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0, party.ByteSize+32)
	data = append(data, sk.ID.Bytes()...)
	data = append(data, sk.sk.Bytes()...)
	return data, nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface.
func (sk *SecretShare) UnmarshalBinary(data []byte) error {
	if len(data) != party.ByteSize+32 {
		return errors.New("SecretShare: data is not the right size")
	}
	sk.ID = party.FromBytes(data)
	data = data[party.ByteSize:]
	_, err := sk.sk.SetCanonicalBytes(data)
	if err != nil {
		return err
	}
	return nil
}

type secretShareJSON struct {
	ID          string `json:"id"`
	SecretShare string `json:"secret"`
}

func (sk *SecretShare) MarshalJSON() ([]byte, error) {
	out := secretShareJSON{
		ID:          sk.ID.String(),
		SecretShare: hex.EncodeToString(sk.sk.Bytes()),
	}
	return json.Marshal(out)
}

// TODO verify group key
func (sk *SecretShare) UnmarshalJSON(data []byte) error {
	var (
		out secretShareJSON
		err error
	)
	if err = json.Unmarshal(data, &out); err != nil {
		return err
	}
	if sk.ID, err = party.IDFromString(out.ID); err != nil {
		return err
	}
	pointBytes, err := hex.DecodeString(out.SecretShare)
	if err != nil {
		return err
	}
	_, err = sk.sk.SetCanonicalBytes(pointBytes)
	return err
}

func (sk *SecretShare) Equal(sk2 *SecretShare) bool {
	if sk.ID != sk2.ID {
		return false
	}
	return sk.sk.Equal(&sk2.sk) == 1
}
