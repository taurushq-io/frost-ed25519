package main

import (
	"errors"
	"testing"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa_test"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestKeygen(t *testing.T) {
	N := party.Size(50)
	T := N / 2

	partySet := eddsa_test.GenerateSet(N)

	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	for id := range partySet.Range() {
		var err error
		states[id], outputs[id], err = frost.NewKeygenState(id, partySet, T, 0)
		if err != nil {
			t.Error(err)
			return
		}
	}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N*(N-1)/2)

	for _, s := range states {
		msgs1, err := partyRoutine(nil, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := partyRoutine(msgsOut1, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := partyRoutine(msgsOut2, s)
		if err != nil {
			t.Error(err)
		}
	}

	id1 := partySet.Sorted()[0]
	if err := states[id1].WaitForError(); err != nil {
		t.Error(err)
	}
	groupKey1 := outputs[id1].Shares.GroupKey()
	publicShares1 := outputs[id1].Shares
	secrets := map[party.ID]*eddsa.SecretShare{}
	for id2 := range partySet.Range() {
		if err := states[id2].WaitForError(); err != nil {
			t.Error(err)
		}
		groupKey2 := outputs[id2].Shares.GroupKey()
		publicShares2 := outputs[id2].Shares
		secrets[id2] = outputs[id2].SecretKey
		if err := CompareOutput(groupKey1, groupKey2, publicShares1, publicShares2); err != nil {
			t.Error(err)
		}
	}

	if err := ValidateSecrets(secrets, groupKey1, publicShares1); err != nil {
		t.Error(err)
	}
}

func CompareOutput(groupKey1, groupKey2 *eddsa.PublicKey, publicShares1, publicShares2 *eddsa.Shares) error {
	if !publicShares1.Equal(publicShares2) {
		return errors.New("shares not equal")
	}
	partyIDs1 := publicShares1.PartySet.Sorted()
	partyIDs2 := publicShares2.PartySet.Sorted()
	if len(partyIDs1) != len(partyIDs2) {
		return errors.New("partyIDs are not the same length")
	}

	for i, id1 := range partyIDs1 {
		if id1 != partyIDs2[i] {
			return errors.New("partyIDs are not the same")
		}

		public1, err := publicShares1.Share(partyIDs1[i])
		if err != nil {
			return err
		}
		public2, err := publicShares2.Share(partyIDs2[i])
		if err != nil {
			return err
		}

		if !public1.Equal(public2) {
			return errors.New("different public keys")
		}
	}

	groupKeyComp1 := publicShares1.GroupKey()
	groupKeyComp2 := publicShares2.GroupKey()

	if !groupKey1.Equal(groupKeyComp1) {
		return errors.New("groupKey1 is not computed the same way")
	}
	if !groupKey2.Equal(groupKeyComp2) {
		return errors.New("groupKey2 is not computed the same way")
	}
	return nil
}

func ValidateSecrets(secrets map[party.ID]*eddsa.SecretShare, groupKey *eddsa.PublicKey, shares *eddsa.Shares) error {
	fullSecret := edwards25519.NewScalar()

	for id, secret := range secrets {
		pk1 := secret.PublicKey()
		pk2, err := shares.Share(id)
		if err != nil {
			return err
		}
		if !pk1.Equal(pk2) {
			return errors.New("pk not the same")
		}

		lagrange, err := shares.PartySet.Lagrange(id)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, secret.Scalar(), fullSecret)
	}

	fullPk := eddsa.NewPublicKeyFromPoint(new(edwards25519.Point).ScalarBaseMult(fullSecret))
	if !groupKey.Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}

	return nil
}
