package helpers

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

// NewPartySlice returns n party.ID s in the range [1, ..., n].
func NewPartySlice(n party.Size) party.IDSlice {
	partyIDs := make([]party.ID, 0, n)
	for i := party.ID(1); i <= n; i++ {
		partyIDs = append(partyIDs, i)
	}
	return partyIDs
}

func GenerateSet(n party.Size) party.IDSlice {
	return party.NewIDSlice(NewPartySlice(n))
}

func PartyRoutine(in [][]byte, s state.State) ([][]byte, error) {
	for _, m := range in {
		var msgTmp messages.Message

		if err := msgTmp.UnmarshalBinary(m); err != nil {
			return nil, fmt.Errorf("failed to unmarshal message: %w", err)
		}
		if err := s.HandleMessage(&msgTmp); err != nil {
			return nil, fmt.Errorf("failed to handle message: %w", err)
		}
	}
	msgsOut := s.ProcessAll()
	out := make([][]byte, 0, len(msgsOut))
	for _, msgOut := range msgsOut {
		if b, err := msgOut.MarshalBinary(); err == nil {
			out = append(out, b)
		} else {
			return nil, err
		}
	}
	if s.IsFinished() {
		err := s.WaitForError()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
