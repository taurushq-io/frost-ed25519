package main

import (
	"errors"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state/hub"
)

func TestKeygen(t *testing.T) {
	N := party.Size(10)
	T := N / 2

	partyIDs := helpers.GenerateSet(N)

	states := map[party.ID]*hub.State{}
	outputs := map[party.ID]*keygen.Output{}

	for _, id := range partyIDs {
		var err error
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, T, 0)
		if err != nil {
			t.Error(err)
			return
		}
	}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N*(N-1)/2)

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			t.Error(err)
		}
	}

	id1 := partyIDs[0]
	if err := states[id1].WaitForError(); err != nil {
		t.Error(err)
	}
	groupKey1 := outputs[id1].Public.GroupKey
	publicShares1 := outputs[id1].Public
	secrets := map[party.ID]*eddsa.SecretShare{}
	for _, id2 := range partyIDs {
		if err := states[id2].WaitForError(); err != nil {
			t.Error(err)
		}
		groupKey2 := outputs[id2].Public.GroupKey
		publicShares2 := outputs[id2].Public
		secrets[id2] = outputs[id2].SecretKey
		if err := CompareOutput(groupKey1, groupKey2, publicShares1, publicShares2); err != nil {
			t.Error(err)
		}
	}

	if err := ValidateSecrets(secrets, groupKey1, publicShares1); err != nil {
		t.Error(err)
	}
}

func CompareOutput(groupKey1, groupKey2 *eddsa.PublicKey, publicShares1, publicShares2 *eddsa.Public) error {
	if !publicShares1.Equal(publicShares2) {
		return errors.New("shares not equal")
	}
	partyIDs1 := publicShares1.PartyIDs
	partyIDs2 := publicShares2.PartyIDs
	if len(partyIDs1) != len(partyIDs2) {
		return errors.New("partyIDs are not the same length")
	}

	for i, id1 := range partyIDs1 {
		if id1 != partyIDs2[i] {
			return errors.New("partyIDs are not the same")
		}

		public1 := publicShares1.Shares[partyIDs1[i]]
		public2 := publicShares2.Shares[partyIDs2[i]]
		if public1.Equal(public2) != 1 {
			return errors.New("different public keys")
		}
	}

	groupKeyComp1 := publicShares1.GroupKey
	groupKeyComp2 := publicShares2.GroupKey

	if !groupKey1.Equal(groupKeyComp1) {
		return errors.New("groupKey1 is not computed the same way")
	}
	if !groupKey2.Equal(groupKeyComp2) {
		return errors.New("groupKey2 is not computed the same way")
	}
	return nil
}

func ValidateSecrets(secrets map[party.ID]*eddsa.SecretShare, groupKey *eddsa.PublicKey, shares *eddsa.Public) error {
	fullSecret := ristretto.NewScalar()

	for id, secret := range secrets {
		pk1 := &secret.Public
		pk2, ok := shares.Shares[id]
		if !ok {
			return errors.New("party %d has no share")
		}

		if pk1.Equal(pk2) != 1 {
			return errors.New("pk not the same")
		}

		lagrange, err := id.Lagrange(shares.PartyIDs)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, &secret.Secret, fullSecret)
	}

	fullPk := eddsa.NewPublicKeyFromPoint(new(ristretto.Element).ScalarBaseMult(fullSecret))
	if !groupKey.Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}

	return nil
}
