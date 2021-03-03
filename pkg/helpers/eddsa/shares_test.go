package eddsa

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func fakeShares(n, t uint32) *Shares {
	shares := make(map[uint32]*edwards25519.Point, n)
	for i := 0; i < int(n); i++ {
		id := rand.Uint32()
		s := scalar.NewScalarUInt32(id)
		p := new(edwards25519.Point).ScalarBaseMult(s)
		shares[id] = p
	}
	return NewShares(shares, t, nil)
}

func TestShares_MarshalJSON(t *testing.T) {
	s := fakeShares(40, 39)

	out, err := json.MarshalIndent(s, "", "    ")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(out))

	var s2 Shares
	err = json.Unmarshal(out, &s2)
	if err != nil {
		t.Error(err)
	}

	if !s.Equal(&s2) {
		t.Error("unmarshalled is not equal")
	}
}

func TestShares_MarshalBinary(t *testing.T) {
	s := fakeShares(40, 39)

	out, err := s.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	var s2 Shares
	err = s2.UnmarshalBinary(out)
	if err != nil {
		t.Error(err)
	}

	if !s.Equal(&s2) {
		t.Error("unmarshalled is not equal")
	}
}
