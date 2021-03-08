package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestSign(t *testing.T) {
	N := party.Size(50)
	T := N - 1

	_, signSet, secretShares, publicShares := setupParties(T, N)

	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*sign.Output{}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	for id := range signSet.Range() {
		var err error
		states[id], outputs[id], err = frost.NewSignState(signSet, secretShares[id], publicShares, MESSAGE, 0)
		if err != nil {
			t.Error(err)
		}
	}

	pk := publicShares.GroupKey()

	var start time.Time
	start = time.Now()
	for _, s := range states {
		msgs1, err := partyRoutine(nil, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}
	fmt.Println("finish round 0", time.Since(start))

	start = time.Now()
	for _, s := range states {
		msgs2, err := partyRoutine(msgsOut1, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}
	fmt.Println("finish round 1", time.Since(start))

	start = time.Now()
	for _, s := range states {
		_, err := partyRoutine(msgsOut2, s)
		if err != nil {
			t.Error(err)
		}
	}
	fmt.Println("finish round 2", time.Since(start))

	sig := outputs[1].Signature
	if sig == nil {
		return
	}
	// validate using classic
	if !ed25519.Verify(pk.ToEd25519(), MESSAGE, sig.ToEd25519()) {
		t.Error("sig failed")
	}
	// Validate using our own function
	if !sig.Verify(MESSAGE, pk) {
		t.Error("sig failed")
	}
	// Check all publicKeys return the same sig
	for id, s := range states {
		if err := s.WaitForError(); err != nil {
			t.Error(err)
		}

		comparedSig := outputs[id].Signature
		sigBytes, err := sig.MarshalBinary()
		if err != nil {
			t.Error(err)
		}

		comparedSigBytes, _ := comparedSig.MarshalBinary()
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(sigBytes, comparedSigBytes) {
			t.Error("sigs not the same")
		}
	}
}
