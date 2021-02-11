package main

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
)

type Handler struct {
	id              uint32
	round           frost.Round
	sendingChannels map[uint32]chan []byte
}

func main() {
	var done chan struct{}

	N := uint32(100)
	T := N / 2
	MaliciousSlack := uint32(2)
	message := []byte("hello")

	keygenHandlers := make(map[uint32]*Handler, N)
	signHandlers := make(map[uint32]*Handler, T+MaliciousSlack)

	partyIDs := make([]uint32, N)
	signerIDs := make([]uint32, T+MaliciousSlack)
	for id := uint32(0); id < N; id++ {
		partyIDs[id] = 2*id + 10
	}
	copy(signerIDs, partyIDs)

	// Setup communication channel
	msgsChans := map[uint32]chan []byte{}
	for _, id := range partyIDs {
		msgsChans[id] = make(chan []byte, N*2)
		//msgsChans[id] = make(chan []byte, N)
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
	pk, _, _, _ := keygenHandlers[party1].round.(frost.KeyGenRound).WaitForKeyGenOutput()
	for _, h := range keygenHandlers {
		h.round.(frost.KeyGenRound).WaitForKeyGenOutput()
	}
	close(done)

	done = make(chan struct{})
	for _, id := range signerIDs {
		_, pkShares, secret, _ := keygenHandlers[id].round.(frost.KeyGenRound).WaitForKeyGenOutput()
		r, err := sign.NewRound(id, pkShares, signerIDs, &secret, message)
		if err != nil {
			panic(err)
		}

		signHandlers[id] = &Handler{
			id:              id,
			round:           r,
			sendingChannels: msgsChans,
		}
		go signHandlers[id].HandleMessage(done)
	}

	signHandlers[party1].round.(frost.SignRound).WaitForSignOutput()
	for _, h := range signHandlers {
		if h.round.(frost.SignRound).WaitForSignOutput().Verify(message, pk) {
			fmt.Println(message, "was correctly signed")
		}
	}
	close(done)
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
	var err error
	if h.round.CanStart() {
		if err = h.round.ProcessMessages(); err != nil {
			return err
		}

		if err = h.round.ProcessRound(); err != nil {
			return err
		}

		msgsOut, err := h.round.GenerateMessages()
		if err != nil {
			return err
		}

		for _, msg := range msgsOut {
			msgBytes, err := msg.MarshalBinary()
			if err != nil {
				fmt.Println(err)
			}

			if msg.To != 0 {
				h.SendMessage(msg.To, msgBytes)
				//go h.SendMessage(msg.To, msgBytes)
			} else {
				for otherID := range h.sendingChannels {
					h.SendMessage(otherID, msgBytes)
					//go h.SendMessage(otherID, msgBytes)
				}
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
