package main

import (
	"github.com/taurusgroup/frost-ed25519/pkg/communication"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
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
				//fmt.Println(err)
			}
			h.ProcessAll()
		case <-h.state.Done():
			err := h.state.Err()
			if err != nil {
				//fmt.Println(err)
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
			//fmt.Println("process all", err)
		}
	}
}

func NewKeyGenHandler(comm communication.Communicator, ID uint32, IDs []uint32, T uint32) (*KeyGenHandler, error) {
	p, err := rounds.NewParameters(ID, IDs)
	if err != nil {
		return nil, err
	}
	s, out, err := frost.NewKeygenState(p, T, comm.Timeout())
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

func NewSignHandler(comm communication.Communicator, ID uint32, IDs []uint32, secret *eddsa.PrivateKey, publicShares *eddsa.Shares, message []byte) (*SignHandler, error) {
	p, err := rounds.NewParameters(ID, IDs)
	if err != nil {
		return nil, err
	}
	s, out, err := frost.NewSignState(p, secret, publicShares, message, comm.Timeout())
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

func (h *KeyGenHandler) WaitForKeygenOutput() (*eddsa.PublicKey, *eddsa.Shares, *eddsa.PrivateKey, error) {
	err := h.state.WaitForError()
	if err != nil {
		return nil, nil, nil, err
	}
	return h.out.Shares.GroupKey(), h.out.Shares, h.out.SecretKey, nil
}

func (h *SignHandler) WaitForSignOutput() (*eddsa.Signature, error) {
	err := h.state.WaitForError()
	if err != nil {
		return nil, err
	}
	return h.out.Signature, nil
}
