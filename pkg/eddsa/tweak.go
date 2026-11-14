package eddsa

import (
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// Tweak returns the public key obtained by adding tweak times the base point.
func (pk *PublicKey) Tweak(tweak *ristretto.Scalar) (*PublicKey, error) {
	if tweak == nil {
		return nil, errors.New("eddsa: missing tweak")
	}
	return pk.tweakPoint(ristretto.NewIdentityElement().ScalarBaseMult(tweak))
}

func (pk *PublicKey) tweakPoint(offset *ristretto.Element) (*PublicKey, error) {
	identity := ristretto.NewIdentityElement()
	if pk == nil || pk.pk.Equal(identity) == 1 {
		return nil, errors.New("eddsa: invalid parent public key")
	}
	point := ristretto.NewIdentityElement().Add(&pk.pk, offset)
	if point.Equal(identity) == 1 {
		return nil, errors.New("eddsa: tweak produces the identity group key")
	}
	return NewPublicKeyFromPoint(point), nil
}

// TweakShare returns a new local share and matching public data for the same
// roster and threshold. Every signer must use the same agreed tweak.
// A full tweaked secret together with the tweak reveals the full parent secret.
func (p *Public) TweakShare(share *SecretShare, tweak *ristretto.Scalar) (*SecretShare, *Public, error) {
	if p == nil || share == nil || tweak == nil {
		return nil, nil, errors.New("eddsa: public data, local share and tweak are required")
	}
	localPoint := p.Shares[share.ID]
	if share.ID == 0 || localPoint == nil || !p.PartyIDs.Contains(share.ID) ||
		localPoint.Equal(ristretto.NewIdentityElement().ScalarBaseMult(&share.Secret)) != 1 {
		return nil, nil, errors.New("eddsa: local share does not match public data")
	}
	offset := ristretto.NewIdentityElement().ScalarBaseMult(tweak)
	group, err := p.GroupKey.tweakPoint(offset)
	if err != nil {
		return nil, nil, err
	}
	points := make(map[party.ID]*ristretto.Element, len(p.PartyIDs))
	identity := ristretto.NewIdentityElement()
	for _, id := range p.PartyIDs {
		point := p.Shares[id]
		if point == nil || point.Equal(identity) == 1 {
			return nil, nil, errors.New("eddsa: invalid parent verification share")
		}
		child := ristretto.NewIdentityElement().Add(point, offset)
		if child.Equal(identity) == 1 {
			return nil, nil, errors.New("eddsa: tweak produces an identity verification share")
		}
		points[id] = child
	}
	local := NewSecretShare(share.ID, ristretto.NewScalar().Add(&share.Secret, tweak))
	return local, &Public{PartyIDs: p.PartyIDs.Copy(), Threshold: p.Threshold, Shares: points, GroupKey: group}, nil
}
