package eddsa

import (
	"encoding/json"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func fakeShares(n, t party.Size) (*Shares, *edwards25519.Scalar) {
	shares := make(map[party.ID]*edwards25519.Point, n)
	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)
	for i := 0; i < int(n); i++ {
		id := party.RandID()
		s := poly.Evaluate(id.Scalar())
		p := new(edwards25519.Point).ScalarBaseMult(s)
		shares[id] = p
	}
	return NewShares(shares, t, nil), secret
}

func TestShares_GroupKey(t *testing.T) {
	var public edwards25519.Point
	var N, T party.Size = 50, 40

	shares := make(map[party.ID]*edwards25519.Point, N)
	secret := scalar.NewScalarRandom()
	public.ScalarBaseMult(secret)
	poly := polynomial.NewPolynomial(T, secret)
	for i := 0; i < int(N); i++ {
		id := party.RandID()
		s := poly.Evaluate(id.Scalar())
		p := new(edwards25519.Point).ScalarBaseMult(s)
		shares[id] = p
	}
	s1 := NewShares(shares, T, &public)
	s2 := NewShares(shares, T, nil)

	if !s1.GroupKey().Equal(s2.GroupKey()) {
		t.Error("group key not equal")
	}
}

func TestShares_MarshalJSON(t *testing.T) {
	var public edwards25519.Point
	shares, secret := fakeShares(40, 38)
	public.ScalarBaseMult(secret)

	if public.Equal(shares.groupKey) != 1 {
		t.Error("group key not equal")
	}
	out, err := json.MarshalIndent(shares, "", "    ")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(out))

	var s2 Shares
	err = json.Unmarshal(out, &s2)
	if err != nil {
		t.Error(err)
	}

	if !shares.Equal(&s2) {
		t.Error("unmarshalled is not equal")
	}
}

func TestShares_MarshalBinary(t *testing.T) {
	var public edwards25519.Point
	shares, secret := fakeShares(40, 38)
	public.ScalarBaseMult(secret)

	if public.Equal(shares.groupKey) != 1 {
		t.Error("group key not equal")
	}
	out, err := shares.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	var s2 Shares
	err = s2.UnmarshalBinary(out)
	if err != nil {
		t.Error(err)
	}

	if !shares.Equal(&s2) {
		t.Error("unmarshalled is not equal")
	}
}
