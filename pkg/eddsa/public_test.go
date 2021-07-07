package eddsa

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func fakeShares(n, t party.Size) (*Public, *ristretto.Scalar) {
	shares := make(map[party.ID]*ristretto.Element, n)
	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)
	for i := 0; i < int(n); i++ {
		id := party.RandID()
		s := poly.Evaluate(id.Scalar())
		p := new(ristretto.Element).ScalarBaseMult(s)
		shares[id] = p
	}
	public, _ := NewPublic(shares, t)
	return public, secret
}

func TestShares_GroupKey(t *testing.T) {
	var public ristretto.Element
	var N, T party.Size = 50, 40

	shares := make(map[party.ID]*ristretto.Element, N)
	secret := scalar.NewScalarRandom()
	public.ScalarBaseMult(secret)
	poly := polynomial.NewPolynomial(T, secret)
	for i := 0; i < int(N); i++ {
		id := party.RandID()
		s := poly.Evaluate(id.Scalar())
		p := new(ristretto.Element).ScalarBaseMult(s)
		shares[id] = p
	}
	s1, err := NewPublic(shares, T)
	assert.NoError(t, err, "")

	publicKey := NewPublicKeyFromPoint(&public)

	if !publicKey.Equal(s1.GroupKey) {
		t.Error("group key not equal")
	}
}

func TestShares_MarshalJSON(t *testing.T) {
	var public ristretto.Element
	shares, secret := fakeShares(40, 38)
	public.ScalarBaseMult(secret)
	publicKey := NewPublicKeyFromPoint(&public)

	if !publicKey.Equal(shares.GroupKey) {
		t.Error("group key not equal")
	}
	out, err := json.MarshalIndent(shares, "", "    ")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(out))

	var s2 Public
	err = json.Unmarshal(out, &s2)
	if err != nil {
		t.Error(err)
	}

	if !shares.Equal(&s2) {
		t.Error("unmarshalled is not equal")
	}
}
