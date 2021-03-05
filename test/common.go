package main

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa_test"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

var MESSAGE = []byte("Hello Everybody")

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
		err := s.WaitForError()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func setupParties(t, n party.Size) (partySet, signSet *party.Set, secretShares map[party.ID]*eddsa.SecretShare, publicShares *eddsa.Shares) {
	var err error
	partySet = eddsa_test.GenerateSet(n)
	_, secretShares = eddsa_test.GenerateSecrets(partySet, t)
	publicShares = eddsa_test.GenerateShares(t, secretShares)
	signIDs := partySet.Take(n + 1)
	signSet, err = party.NewSet(signIDs)
	if err != nil {
		panic(err)
	}
	return
}
