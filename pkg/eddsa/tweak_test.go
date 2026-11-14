package eddsa

import (
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestTweakShares(t *testing.T) {
	// f(x) = 5 + 2x, shared among three parties with threshold two.
	secret := party.ID(5).Scalar()
	slope := party.ID(2).Scalar()
	tweak := party.ID(9).Scalar()
	points := make(map[party.ID]*ristretto.Element)
	shares := make(map[party.ID]*SecretShare)
	for _, id := range []party.ID{1, 2, 3} {
		share := NewSecretShare(id, ristretto.NewScalar().MultiplyAdd(slope, id.Scalar(), secret))
		shares[id] = share
		points[id] = &share.Public
	}
	public, err := NewPublic(points, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := NewPublicKeyFromPoint(ristretto.NewIdentityElement().ScalarBaseMult(ristretto.NewScalar().Add(secret, tweak)))
	key, err := public.GroupKey.Tweak(tweak)
	if err != nil || !key.Equal(want) {
		t.Fatalf("unexpected tweaked group key: %v", err)
	}
	for _, id := range public.PartyIDs {
		local, updated, err := public.TweakShare(shares[id], tweak)
		if err != nil {
			t.Fatal(err)
		}
		if local.ID != id || !updated.GroupKey.Equal(want) ||
			!updated.PartyIDs.Equal(public.PartyIDs) || updated.Threshold != public.Threshold ||
			local.Public.Equal(updated.Shares[id]) != 1 ||
			!computeGroupKey(party.IDSlice{1, 3}, updated.Shares).Equal(want) {
			t.Fatalf("inconsistent tweaked shares for party %d", id)
		}
		if shares[id].Secret.Equal(ristretto.NewScalar().MultiplyAdd(slope, id.Scalar(), secret)) != 1 ||
			!public.GroupKey.Equal(NewPublicKeyFromPoint(ristretto.NewIdentityElement().ScalarBaseMult(secret))) {
			t.Fatal("parent key material was mutated")
		}
	}
	if _, err := public.GroupKey.Tweak(ristretto.NewScalar().Negate(secret)); err == nil {
		t.Fatal("accepted identity group key")
	}
	if _, _, err := public.TweakShare(shares[1], ristretto.NewScalar().Negate(&shares[2].Secret)); err == nil {
		t.Fatal("accepted identity verification share")
	}
	if _, _, err := public.TweakShare(NewSecretShare(1, slope), tweak); err == nil {
		t.Fatal("accepted a mismatched local share")
	}
}
