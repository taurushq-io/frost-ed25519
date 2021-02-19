package main

import (
	"fmt"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	round2 "github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type Handler struct {
	id              uint32
	round           round2.Round
	sendingChannels map[uint32]chan []byte
}

func FROSTest(N, T uint32) {
	var done chan struct{}

	fmt.Printf("(n, t) = (%v, %v): ", N, T)

	message := []byte("hello")

	keygenHandlers := make(map[uint32]*Handler, N)
	signHandlers := make(map[uint32]*Handler, T+1)

	partyIDs := make([]uint32, N)
	signerIDs := make([]uint32, T+1)

	for id := uint32(0); id < N; id++ {
		partyIDs[id] = 2*id + 10
	}

	copy(signerIDs, partyIDs)

	// Setup communication channel
	msgsChans := map[uint32]chan []byte{}
	for _, id := range partyIDs {
		msgsChans[id] = make(chan []byte, N)
	}

	done = make(chan struct{})

	for _, id := range partyIDs {
		r0, _ := keygen.NewRound(id, T, partyIDs)
		keygenHandlers[id] = &Handler{
			id:              id,
			round:           r0,
			sendingChannels: msgsChans,
		}
		go keygenHandlers[id].HandleMessage(done)
	}

	party1 := partyIDs[0]
	// obtain the public key from the first party and wait for the others
	pk, _, _, err := keygenHandlers[party1].round.(round2.KeyGenRound).WaitForKeygenOutput()
	if err != nil {
		panic(err)
	}
	for _, h := range keygenHandlers {
		err = h.round.WaitForFinish()
		if err != nil {
			panic(err)
		}
	}
	close(done)

	done = make(chan struct{})
	for _, id := range signerIDs {
		pkOther, pkShares, secret, _ := keygenHandlers[id].round.(round2.KeyGenRound).WaitForKeygenOutput()
		r, err := sign.NewRound(id, pkShares, signerIDs, secret, message)
		if err != nil {
			panic(err)
		}
		if !pkOther.Equal(pk) {
			panic("bad pk")
		}

		signHandlers[id] = &Handler{
			id:              id,
			round:           r,
			sendingChannels: msgsChans,
		}
		go signHandlers[id].HandleMessage(done)
	}

	_, err = signHandlers[party1].round.(round2.SignRound).WaitForSignOutput()
	if err != nil {
		panic(err)
	}

	failures := 0

	for _, h := range signHandlers {
		s, _ := h.round.(round2.SignRound).WaitForSignOutput()
		if !s.Verify(message, pk) {
			failures++
		}
	}
	if failures != 0 {
		fmt.Printf("%v signatures verifications failed\n", failures)
	} else {
		fmt.Printf("ok\n")
	}

	close(done)
}

func main() {
	ns := []uint32{5, 10, 50, 100}

	for _, n := range ns {
		start := time.Now()
		FROSTest(n, n/2)
		elapsed := time.Since(start)
		fmt.Printf("%s\n", elapsed)
	}
}

func (h *Handler) HandleMessage(done chan struct{}) {
	var err error
	incoming := h.sendingChannels[h.id]
	if err = h.ProcessAll(); err != nil {
		fmt.Println(err)
	}
	for {
		select {
		case msg := <-incoming:
			if msg != nil {
				msgTmp := messages.Message{}
				if err = msgTmp.UnmarshalBinary(msg); err != nil {
					fmt.Println(err)
				}
				if err = h.round.StoreMessage(&msgTmp); err != nil {
					fmt.Println(err)
				}
			}
			if err = h.ProcessAll(); err != nil {
				fmt.Println(err)
			}

		case <-done:
			return
		}
	}
}

func (h *Handler) ProcessAll() error {
	h.round.ProcessMessages()

	h.round.ProcessRound()

	msgsOut := h.round.GenerateMessages()

	for _, msg := range msgsOut {
		msgBytes, err := msg.MarshalBinary()
		if err != nil {
			fmt.Println(err)
		}

		if msg.To != 0 {
			go h.SendMessage(msg.To, msgBytes)
		} else {
			for otherID := range h.sendingChannels {
				go h.SendMessage(otherID, msgBytes)
			}
		}
	}
	h.round = h.round.NextRound()
	return nil
}

func (h *Handler) SendMessage(to uint32, msg []byte) {
	if to == h.id {
		return
	}
	h.sendingChannels[to] <- msg
}
