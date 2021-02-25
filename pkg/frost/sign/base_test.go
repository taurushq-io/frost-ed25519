package sign

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func TestRound(t *testing.T) {
	N := uint32(100)
	T := N / 2

	_, AllPartyIDs, publicKeys, secrets := generateFakeParties(T, N)

	partyIDs := AllPartyIDs[:T+1]

	Rounds := make(map[uint32]rounds.SignRound)

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	message := []byte("hello")

	for _, id := range partyIDs {
		r0, _ := NewRound(id, partyIDs, secrets[id], publicKeys, message)
		Rounds[id] = r0.(rounds.SignRound)
	}

	rTmp := Rounds[1]
	pk := rTmp.(*round0).GroupKey
	pkKey := eddsa.NewPublicKeyFromPoint(&pk)

	a := func(in [][]byte, r rounds.Round) (out [][]byte, rNext rounds.Round) {
		out = make([][]byte, 0, N-1)
		for _, m := range in {
			msgTmp := messages.Message{}
			err := msgTmp.UnmarshalBinary(m)
			assert.NoError(t, err, "failed to store message")
			assert.NoError(t, r.StoreMessage(&msgTmp), "failed to store message")
		}
		r.ProcessMessages()
		r.ProcessRound()
		msgsOut := r.GenerateMessages()
		for _, msgOut := range msgsOut {
			if b, err := msgOut.MarshalBinary(); err == nil {
				out = append(out, b)
			} else {
				fmt.Println(err)
				continue
			}
		}
		rNext = r.NextRound()
		return
	}

	for id := range Rounds {
		msgs1, nextR := a(nil, Rounds[id])
		msgsOut1 = append(msgsOut1, msgs1...)
		Rounds[id] = nextR.(rounds.SignRound)
	}

	for id := range Rounds {
		msgs2, nextR := a(msgsOut1, Rounds[id])
		msgsOut2 = append(msgsOut2, msgs2...)
		Rounds[id] = nextR.(rounds.SignRound)
	}

	for id := range Rounds {
		_, nextR := a(msgsOut2, Rounds[id])
		Rounds[id] = nextR.(rounds.SignRound)
	}

	sig, err := Rounds[1].WaitForSignOutput()
	require.NoError(t, err)
	sigBytes, err := sig.MarshalBinary()
	require.NoError(t, err)

	// validate using classic
	assert.True(t, ed25519.Verify(pkKey.ToEdDSA(), message, sigBytes))

	// Validate using our own function
	assert.True(t, sig.Verify(message, pkKey))

	// Check all publicKeys return the same sig
	for _, id := range partyIDs {
		comparedSig, _ := Rounds[id].WaitForSignOutput()
		comparedSigBytes, _ := comparedSig.MarshalBinary()
		require.NoError(t, err)
		assert.True(t, bytes.Equal(sigBytes, comparedSigBytes))
	}
}

func generateFakeParties(t, n uint32) (*edwards25519.Scalar, []uint32, eddsa.PublicKeyShares, map[uint32]*eddsa.PrivateKey) {
	allParties := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i + 1
	}

	secret := scalar.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)
	shares := poly.EvaluateMultiple(allParties)

	secrets := map[uint32]*eddsa.PrivateKey{}
	parties := eddsa.PublicKeyShares{}

	for _, id := range allParties {
		pk := new(edwards25519.Point).ScalarBaseMult(shares[id])
		parties[id] = eddsa.NewPublicKeyFromPoint(pk)
		secrets[id] = eddsa.NewPrivateKeyFromScalar(shares[id], parties[id])
	}

	return secret, allParties, parties, secrets
}
