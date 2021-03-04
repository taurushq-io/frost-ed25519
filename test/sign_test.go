package main

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	frost2 "github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestSign(t *testing.T) {
	N := uint32(100)
	T := N - 1

	_, AllPartyIDs, shares, secrets := generateFakeParties(T, N)

	partyIDs := AllPartyIDs[:T+1]

	states := map[uint32]*state.State{}
	outputs := map[uint32]*sign.Output{}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	message := []byte("hello")

	for _, id := range partyIDs {
		p, err := rounds.NewParameters(id, partyIDs)
		if err != nil {
			t.Error(err)
			return
		}
		states[id], outputs[id], err = frost2.NewSignState(p, secrets[id], shares, message, 0)
		if err != nil {
			t.Error(err)
		}
	}

	pk := shares.GroupKey()

	for _, s := range states {
		msgs1, err := partyRoutine(nil, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := partyRoutine(msgsOut1, s)
		if err != nil {
			t.Error(err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := partyRoutine(msgsOut2, s)
		if err != nil {
			t.Error(err)
		}
	}
	sig := outputs[1].Signature
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

func generateFakeParties(t, n uint32) (*edwards25519.Scalar, []uint32, *eddsa.Shares, map[uint32]*eddsa.PrivateKey) {
	allParties := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i + 1
	}

	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)
	shares := poly.EvaluateMultiple(allParties)

	secrets := map[uint32]*eddsa.PrivateKey{}
	sharesPublic := map[uint32]*edwards25519.Point{}

	for _, id := range allParties {
		sharesPublic[id] = new(edwards25519.Point).ScalarBaseMult(shares[id])
		secrets[id] = eddsa.NewPrivateKeyFromScalar(shares[id])
	}

	return secret, allParties, eddsa.NewShares(sharesPublic, t, nil), secrets
}
