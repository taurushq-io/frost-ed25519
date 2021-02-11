package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
)

func TestHandler_HandleMessage(t *testing.T) {
	N := uint32(50)
	T := N / 2

	handlers := make(map[uint32]*Handler, N)

	partyIDs := make([]uint32, 0, N)
	for id := uint32(1); id <= N; id++ {
		partyIDs = append(partyIDs, id)
	}

	done := make(chan struct{})
	msgsChans := map[uint32]chan []byte{}
	for _, id := range partyIDs {
		msgsChans[id] = make(chan []byte, N*2)
	}
	for _, id := range partyIDs {
		r0, _ := keygen.NewRound(id, T, partyIDs)
		h := Handler{
			id:              id,
			round:           r0,
			sendingChannels: msgsChans,
		}
		handlers[id] = &h
		go h.HandleMessage(done)
		msgsChans[id] <- nil
	}

	pk, _, _, _ := handlers[1].round.(frost.KeyGenRound).WaitForKeyGenOutput()
	for _, h := range handlers {
		pk2, _, _, _ := h.round.(frost.KeyGenRound).WaitForKeyGenOutput()
		assert.Equal(t, 1, pk.Point.Equal(pk2.Point))
	}
	close(done)

	message := []byte("hello")

	MaliciousSlack := uint32(3)

	done2 := make(chan struct{})
	handlersSign := make(map[uint32]*Handler, T+MaliciousSlack)
	partyIDsSign := append([]uint32{}, partyIDs[:T+MaliciousSlack]...)
	for _, id := range partyIDsSign {
		h := handlers[id]
		_, pkShares, secret, _ := h.round.(frost.KeyGenRound).WaitForKeyGenOutput()
		r, err := sign.NewRound(h.id, pkShares, partyIDsSign, &secret, message)
		if err != nil {
			fmt.Println(err)
		}

		hSign := &Handler{
			id:              h.id,
			round:           r,
			sendingChannels: msgsChans,
		}
		handlersSign[id] = hSign
		go handlersSign[id].HandleMessage(done2)
		//fmt.Println(h.round.WaitForKeyGenOutput())
	}
	for id := range handlersSign {
		msgsChans[id] <- nil
	}
	s := handlersSign[1].round.(frost.SignRound).WaitForSignOutput()
	assert.True(t, s.Verify(message, pk))

	close(done2)

}

func TestHandler_ProcessAll(t *testing.T) {
}

func TestHandler_SendMessage(t *testing.T) {
}
