package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestSign(t *testing.T) {
	N := party.Size(50)
	T := N - 1

	_, AllPartyIDs, shares, secrets := generateFakeParties(T, N)

	partyIDs := AllPartyIDs[:T+1]

	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*sign.Output{}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	message := []byte("hello")

	for _, id := range partyIDs {
		set, err := party.NewSetWithSelf(id, partyIDs)
		if err != nil {
			t.Error(err)
			return
		}
		states[id], outputs[id], err = frost.NewSignState(set, secrets[id], shares, message, 0)
		if err != nil {
			t.Error(err)
		}
	}

	pk := shares.GroupKey()

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
	if !ed25519.Verify(pk.ToEdDSA(), message, sig.ToEdDSA()) {
		t.Error("sig failed")
	}
	// Validate using our own function
	if !sig.Verify(message, pk) {
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

func generateFakeParties(t, n party.Size) (*edwards25519.Scalar, []party.ID, *eddsa.Shares, map[party.ID]*eddsa.PrivateKey) {
	allParties := make([]party.ID, n)
	for i := party.ID(0); i < n; i++ {
		allParties[i] = i + 1
	}

	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)

	shares := map[party.ID]*edwards25519.Scalar{}
	secrets := map[party.ID]*eddsa.PrivateKey{}
	sharesPublic := map[party.ID]*edwards25519.Point{}

	for _, id := range allParties {
		shares[id] = poly.Evaluate(id.Scalar())
		secrets[id] = eddsa.NewPrivateKeyFromScalar(shares[id])
		sharesPublic[id] = secrets[id].PublicKey().Point()
	}

	return secret, allParties, eddsa.NewShares(sharesPublic, t, nil), secrets
}
