package eddsa

import (
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
)

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

func TestSecretShare_MarshalJSON(t *testing.T) {
	secret := scalar.NewScalarUInt32(42)
	s := NewSecretShare(42, secret)
	dataJson, err := s.MarshalJSON()
	if err != nil {
		t.Error(err)
	}
	var s2 SecretShare
	err = s2.UnmarshalJSON(dataJson)
	if err != nil {
		t.Error(err)
	}
	if !s2.Equal(s) {
		t.Error("unmarshalled share is not the same")
	}
}

func TestSecretShare_MarshalBinary(t *testing.T) {
	secret := scalar.NewScalarUInt32(42)
	s := NewSecretShare(42, secret)
	dataBin, err := s.MarshalBinary()
	if err != nil {
		t.Error(err)
	}
	var s2 SecretShare
	err = s2.UnmarshalBinary(dataBin)
	if err != nil {
		t.Error(err)
	}
	if !s2.Equal(s) {
		t.Error("unmarshalled share is not the same")
	}
}
