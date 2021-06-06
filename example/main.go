/*
This file is not intended to be run by itself and serves mostly as an example of how to interact with FROST-Ed25519.
*/
package example

import (
	"crypto/ed25519"
	"log"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

// these channels are placeholders for a transport layer
var messagesIn, messagesOut chan *messages.Message

func MessageRoutine(msgsIn, msgsOut chan *messages.Message, s *state.State) {
	for {
		select {
		case msg := <-msgsIn:
			// The State performs some verification to check that the message is relevant for this protocol
			if err := s.HandleMessage(msg); err != nil {
				// An error here may not be too bad, it is not necessary to abort.
				log.Println("failed to handle message", err)
				continue
			}

			// We ask the State for the next round of messages, and must handle them here.
			// If an abort has occurred, then no messages are returned.
			for _, msgOut := range s.ProcessAll() {
				msgsOut <- msgOut
			}

		case <-s.Done():
			// s.Done() closes either when an abort has been called, or when the output has successfully been computed.
			// If an error did occur, we can handle it here
			err := s.WaitForError()
			if err != nil {
				log.Panicln("protocol aborted: ", err)
			}
			// In the main thread, it is safe to use the Output.
			return
		}
	}
}

func main() {
	selfID := party.ID(1)
	threshold := party.Size(2)
	set := party.NewIDSlice([]party.ID{selfID, 2, 42, 8})

	keygenState, keygenOutput, err := frost.NewKeygenState(selfID, set, threshold, 2*time.Second)
	if err != nil {
		panic(err)
	}

	// Handle messages in another thread
	go MessageRoutine(messagesIn, messagesOut, keygenState)

	// Block until the protocol has finished
	err = keygenState.WaitForError()
	if err != nil {
		// the protocol has aborted
	}
	// It is now safe to access the output
	public := keygenOutput.Public
	groupKey := public.GroupKey
	secretShare := keygenOutput.SecretKey

	message := []byte("example")

	// Get a smaller set of size t+1
	signers := party.NewIDSlice([]party.ID{selfID, 2, 8})
	signState, signOutput, err := frost.NewSignState(signers, secretShare, public, message, 1*time.Second)
	if err != nil {
		panic(err)
	}

	// Handle messages in another thread
	go MessageRoutine(messagesIn, messagesOut, signState)

	// Block until the protocol has finished
	err = signState.WaitForError()
	if err != nil {
		// the protocol has aborted
	}

	// Verify signatyre
	groupSig := signOutput.Signature
	if !ed25519.Verify(groupKey.ToEd25519(), message, groupSig.ToEd25519()) {
		log.Println("failed to validate single signature")
	}
}
