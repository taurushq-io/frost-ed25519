package frost

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/communication"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

// handler holds the information for a certain Round by a participant.
// It makes it easier to work with the underlying Round interface.
type handler struct {
	round    rounds.Round
	comm     communication.Communicator
	finished chan struct{}
}

type (
	KeyGenHandler struct {
		*handler
	}

	SignHandler struct {
		*handler
	}
)

// done is called by
func (h *handler) done() {
	select {
	case <-h.finished:
		return
	default:
		close(h.finished)
	}
}

func (h *handler) Cancel() {

}

// HandleMessage is a blocking function that exits
func (h *handler) HandleMessage() {
	incoming := h.comm.Incoming()
	h.ProcessAll()

	for {
		select {
		case msg := <-incoming:
			if err := h.round.StoreMessage(msg); err != nil {
				fmt.Println(err)
			}
			h.ProcessAll()
		case <-h.finished:
			h.comm.Done()
			return
		}
	}
}

func (h *handler) ProcessAll() {
	h.round.ProcessMessages()

	h.round.ProcessRound()

	msgsOut := h.round.GenerateMessages()

	for _, msg := range msgsOut {
		err := h.comm.Send(msg)
		if err != nil {
			fmt.Println(err)
		}
	}
	h.round = h.round.NextRound()
}

func NewKeyGenHandler(comm communication.Communicator, ID uint32, IDs []uint32, T uint32) (*KeyGenHandler, error) {
	r, err := keygen.NewRound(ID, T, IDs)
	if err != nil {
		return nil, err
	}
	h := &handler{
		round:    r,
		comm:     comm,
		finished: make(chan struct{}),
	}
	go h.HandleMessage()
	return &KeyGenHandler{h}, nil
}

func NewSignHandler(comm communication.Communicator, ID uint32, IDs []uint32, secret *eddsa.PrivateKey, publicShares *eddsa.Shares, message []byte) (*SignHandler, error) {
	r, err := sign.NewRound(ID, IDs, secret, publicShares, message)
	if err != nil {
		return nil, err
	}
	h := &handler{
		round:    r,
		comm:     comm,
		finished: make(chan struct{}),
	}
	go h.HandleMessage()
	return &SignHandler{h}, nil
}

func (h *KeyGenHandler) WaitForKeygenOutput() (groupKey *eddsa.PublicKey, publicShares *eddsa.Shares, secretKeyShare *eddsa.PrivateKey, err error) {
	defer h.done()
	return h.round.(rounds.KeyGenRound).WaitForKeygenOutput()
}

func (h *SignHandler) WaitForSignOutput() (signature *eddsa.Signature, err error) {
	defer h.done()
	return h.round.(rounds.SignRound).WaitForSignOutput()
}
