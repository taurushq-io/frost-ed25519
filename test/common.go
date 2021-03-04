package main

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func partyRoutine(in [][]byte, s *state.State) ([][]byte, error) {

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
		if err := s.WaitForError(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
