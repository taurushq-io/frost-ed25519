package main

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state/spoke"
)

var MSG = []byte("Hello Everybody")

func setupPartiesLocal(t, n party.Size) (partyIDs, signIDs party.IDSlice, secretShares map[party.ID]*eddsa.SecretShare, publicShares *eddsa.Public) {
	partyIDs = helpers.GenerateSet(n)
	_, secretShares = helpers.GenerateSecrets(partyIDs, t)
	publicShares = helpers.GeneratePublic(t, secretShares)
	signIDs = partyIDs[:t+1]
	return
}

func TestSign(t *testing.T) {
	N := party.Size(10)
	T := N - 1

	hubID := party.ID(N + 1)
	_, signSet, secretShares, publicShares := setupPartiesLocal(T, N)

	signSetWithHub := append(signSet, hubID)

	states := map[party.ID]*spoke.State{}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	coorState, output, err := frost.NewCoordinatorState(hubID, signSetWithHub, publicShares, MSG, 0)
	if err != nil {
		t.Error(err)
	}

	for _, id := range signSet {
		var err error
		states[id], err = frost.NewSignerState(hubID, signSet, secretShares[id], publicShares, 0)
		if err != nil {
			t.Error(err)
		}
	}

	pk := publicShares.GroupKey

	var start time.Time
	start = time.Now()
	preSignRequest, err := helpers.PartyRoutine(nil, coorState)
	if err != nil {
		t.Error(err)
	}
	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(preSignRequest, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}
	fmt.Println("finish round 0", time.Since(start))

	start = time.Now()
	signRequest, err := helpers.PartyRoutine(msgsOut1, coorState)
	if err != nil {
		t.Error(err)
	}
	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(signRequest, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}
	fmt.Println("finish round 1", time.Since(start))

	start = time.Now()

	fmt.Println("finish round 2", time.Since(start))
	_, err = helpers.PartyRoutine(msgsOut2, coorState)
	if err != nil {
		t.Error(err)
	}
	sig := output.Signature
	if sig == nil {
		return
	}
	// validate using classic
	if !ed25519.Verify(pk.ToEd25519(), MSG, sig.ToEd25519()) {
		t.Error("sig ed25519 failed")
	}
	// Validate using our own function
	if !pk.Verify(MSG, sig) {
		t.Error("sig custom failed")
	}

	fmt.Println("success")
}
