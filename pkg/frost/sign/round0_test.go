package sign

import (
	"filippo.io/edwards25519"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"testing"
)

func TestRound(t *testing.T) {
	N := uint32(10)
	T := uint32(5)

	secret, AllPartyIDs, parties, secrets := generateFakeParties(T, N)

	partyIDs := AllPartyIDs[:T]

	rounds := make(map[uint32]frost.Round, len(partyIDs))

	message := []byte("hello")

	for _, id := range partyIDs {
		rounds[id] = NewRound(id, parties, partyIDs, secrets[id], message)
	}

	rTmp := rounds[1].(*round0)
	pkcomp := new(edwards25519.Point).ScalarBaseMult(secret)
	assert.Equal(t, 1, rTmp.GroupKey.Point().Equal(pkcomp))

	msgsOut1 := make([][]byte, 0, N*N)
	msgsOut2 := make([][]byte, 0, N*N)
	for _, id := range partyIDs {
		r := rounds[id]
		if r.CanProcess() {
			msgOut, err := r.ProcessRound()
			if err != nil {
				fmt.Println(err)
			}
			msgsOut1 = append(msgsOut1, msgOut...)

			newR := r.NextRound()
			rounds[id] = newR
		}

	}

	for _, id := range partyIDs {
		r := rounds[id]
		for _, m := range msgsOut1 {
			err := r.StoreMessage(m)
			if err != nil {
				fmt.Println(err)
			}
		}
		if r.CanProcess() {
			msgOut, err := r.ProcessRound()
			if err != nil {
				fmt.Println(err)
			}
			msgsOut2 = append(msgsOut2, msgOut...)

			newR := r.NextRound()
			rounds[id] = newR
		}

	}

	outMsgs := make([][]byte, 0, N*N)
	for _, id := range partyIDs {
		r := rounds[id]
		for _, m := range msgsOut2 {
			err := r.StoreMessage(m)
			if err != nil {
				fmt.Println(err)
			}
		}
		if r.CanProcess() {
			msgOut, err := r.ProcessRound()
			if err != nil {
				fmt.Println(err)
			}
			outMsgs = append(outMsgs, msgOut...)

			newR := r.NextRound()
			rounds[id] = newR
		}
	}

	//_, _, c := frost.DecodeBytes(outMsgs[0])
	m1 := new(frost.Signature)
	err := m1.UnmarshalBinary(outMsgs[0])
	assert.NoError(t, err)
	for _, m := range outMsgs {
		msgType, _ := frost.DecodeBytes(m)
		assert.Equal(t, frost.MessageTypeSignature, msgType)
		msg := new(frost.Signature)

		err = msg.UnmarshalBinary(m)
		assert.NoError(t, err)
		assert.Equal(t, 1, msg.R.Equal(m1.R))
		assert.Equal(t, 1, msg.S.Equal(m1.S))
	}

	assert.True(t, m1.Verify(message, rTmp.GroupKey))

	print("")
}
