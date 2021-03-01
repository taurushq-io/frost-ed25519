package keygen

import (
	"errors"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func TestKeygen(t *testing.T) {
	N := uint32(10)
	T := N / 2

	partyIDs := make([]uint32, 0, N)
	for id := uint32(1); id <= N; id++ {
		partyIDs = append(partyIDs, id)
	}

	Rounds := make(map[uint32]rounds.KeyGenRound)

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N*(N-1)/2)

	for _, id := range partyIDs {
		r0, _ := NewRound(id, T, partyIDs, 0)
		Rounds[id] = r0.(*round0)
	}

	doRound := func(in [][]byte, r rounds.Round) (out [][]byte, rNext rounds.Round) {
		out = make([][]byte, 0, N-1)
		for _, m := range in {
			msgTmp := messages.Message{}
			err := msgTmp.UnmarshalBinary(m)
			assert.NoError(t, err, "failed to store message")

			assert.NoError(t, r.StoreMessage(&msgTmp), "failed to store message")
		}

		r.ProcessMessages()
		r.ProcessRound()
		for _, msgOut := range r.GenerateMessages() {
			if b, err := msgOut.MarshalBinary(); err == nil {
				out = append(out, b)
			} else {
				fmt.Println(err)
				return
			}
		}
		return out, r.NextRound()
	}

	for id, r0 := range Rounds {
		msgs1, nextR := doRound(nil, r0)
		msgsOut1 = append(msgsOut1, msgs1...)
		Rounds[id] = nextR.(rounds.KeyGenRound)
	}

	for id, r1 := range Rounds {
		msgs2, nextR := doRound(msgsOut1, r1)
		msgsOut2 = append(msgsOut2, msgs2...)
		Rounds[id] = nextR.(rounds.KeyGenRound)
	}

	for id := range Rounds {
		doRound(msgsOut2, Rounds[id])
	}

	id1 := partyIDs[0]
	err := <-Rounds[id1].Error()
	assert.NoError(t, err)
	groupKey1, publicShares1, _ := Rounds[id1].Output()
	secrets := map[uint32]*eddsa.PrivateKey{}
	for _, id2 := range partyIDs {

		err := <-Rounds[id2].Error()
		assert.NoError(t, err)
		groupKey2, publicShares2, secret2 := Rounds[id2].Output()
		secrets[id2] = secret2
		assert.NoError(t, err, "output failed")
		assert.NoError(t, CompareOutput(groupKey1, groupKey2, publicShares1, publicShares2), "comparison failed")
	}
	assert.NoError(t, ValidateSecrets(secrets, groupKey1, publicShares1))
}

func CompareOutput(groupKey1, groupKey2 *eddsa.PublicKey, publicShares1, publicShares2 *eddsa.Shares) error {
	partyIDs1 := publicShares1.PartyIDs()
	partyIDs2 := publicShares2.PartyIDs()
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

	groupKeyComp1, err := publicShares1.GroupKey(nil)
	if err != nil {
		return err
	}
	groupKeyComp2, err := publicShares2.GroupKey(nil)
	if err != nil {
		return err
	}

	if !groupKey1.Equal(groupKeyComp1) {
		return errors.New("groupKey1 is not computed the same way")
	}
	if !groupKey2.Equal(groupKeyComp2) {
		return errors.New("groupKey2 is not computed the same way")
	}
	return nil
}

func ValidateSecrets(secrets map[uint32]*eddsa.PrivateKey, groupKey *eddsa.PublicKey, shares *eddsa.Shares) error {
	fullSecret := edwards25519.NewScalar()
	allIDs := shares.PartyIDs()

	for id, secret := range secrets {
		pk1 := secret.PublicKey()
		pk2, err := shares.Share(id)
		if err != nil {
			return err
		}
		if !pk1.Equal(pk2) {
			return errors.New("pk not the same")
		}

		lagrange, err := shares.Lagrange(id, allIDs)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, secret.Scalar(), fullSecret)
	}

	fullSk := eddsa.NewPrivateKeyFromScalar(fullSecret)
	fullPk := eddsa.NewPublicKeyFromPoint(new(edwards25519.Point).ScalarBaseMult(fullSecret))
	if !fullSk.PublicKey().Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}
	if !groupKey.Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}

	return nil
}
