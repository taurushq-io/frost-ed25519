package main

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
	"github.com/taurusgroup/frost-ed25519/test/communication"
)

// handler holds the information for a certain Round by a participant.
// It makes it easier to work with the underlying Round interface.
type handler struct {
	state *state.State
	comm  communication.Communicator
}

type (
	KeyGenHandler struct {
		*handler
		out *keygen.Output
	}

	SignHandler struct {
		*handler
		out *sign.Output
	}
)

// HandleMessage is a blocking function that exits
func (h *handler) HandleMessage() {
	h.ProcessAll()

	for {
		select {
		case msg := <-h.comm.Incoming():
			if msg == nil {
				continue
			}
			if err := h.state.HandleMessage(msg); err != nil {
				fmt.Println("handle message", err)
			}
			h.ProcessAll()
		case <-h.state.Done():
			err := h.state.Err()
			if err != nil {
				fmt.Println("done with err: ", err)
			}
			return
		}
	}
}

func (h *handler) ProcessAll() {
	msgsOut := h.state.ProcessAll()

	for _, msg := range msgsOut {
		err := h.comm.Send(msg)
		if err != nil {
			fmt.Println("process all", err)
		}
	}
}

func NewKeyGenHandler(comm communication.Communicator, ID party.ID, IDs []party.ID, T party.Size) (*KeyGenHandler, error) {
	set, err := party.NewSet(IDs)
	if err != nil {
		return nil, err
	}
	s, out, err := frost.NewKeygenState(ID, set, T, comm.Timeout())
	if err != nil {
		return nil, err
	}
	h := &handler{
		state: s,
		comm:  comm,
	}
	go h.HandleMessage()
	return &KeyGenHandler{
		handler: h,
		out:     out,
	}, nil
}

func NewSignHandler(comm communication.Communicator, ID party.ID, IDs []party.ID, secret *eddsa.SecretShare, publicShares *eddsa.Shares, message []byte) (*SignHandler, error) {
	set, err := party.NewSet(IDs)
	if err != nil {
		return nil, err
	}
	s, out, err := frost.NewSignState(set, secret, publicShares, message, comm.Timeout())
	if err != nil {
		return nil, err
	}
	h := &handler{
		state: s,
		comm:  comm,
	}
	go h.HandleMessage()
	return &SignHandler{
		handler: h,
		out:     out,
	}, nil
}
