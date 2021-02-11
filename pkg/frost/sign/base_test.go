package sign

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/common"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
)

func TestRound(t *testing.T) {
	N := uint32(10)
	T := uint32(5)

	_, AllPartyIDs, publicKeys, secrets := generateFakeParties(T, N)

	partyIDs := AllPartyIDs[:T+1]

	rounds := make(map[uint32]frost.SignRound)
	//rounds1 := make(map[uint32]*round1)
	//rounds2 := make(map[uint32]*round2)

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	message := []byte("hello")

	for _, id := range partyIDs {
		r0, _ := NewRound(id, publicKeys, partyIDs, secrets[id], message)
		rounds[id] = r0.(frost.SignRound)
	}

	rTmp := rounds[1]
	pk := rTmp.(*base).Y
	pkKey := eddsa.PublicKey{Point: &pk}

	a := func(in [][]byte, r frost.Round) (out [][]byte, rNext frost.Round) {
		out = make([][]byte, 0, N-1)
		for _, m := range in {

			msgTmp := messages.Message{}
			err := msgTmp.UnmarshalBinary(m)
			assert.NoError(t, err, "failed to store message")

			if msgTmp.From == r.ID() {
				continue
			}

			if msgTmp.To == 0 {
				assert.NoError(t, r.StoreMessage(&msgTmp), "failed to store message")
			} else if msgTmp.To == r.ID() {
				assert.NoError(t, r.StoreMessage(&msgTmp), "failed to store message")
			}
		}
		if r.CanStart() {
			err := r.ProcessMessages()
			if err != nil {
				assert.NoError(t, err, "failed to process")
			}
			err = r.ProcessRound()
			if err != nil {
				assert.NoError(t, err, "failed to process")
			}

			msgsOut, err := r.GenerateMessages()
			assert.NoError(t, err, "failed to process")
			//rNext = r.NextRound()
			for _, msgOut := range msgsOut {
				if b, err := msgOut.MarshalBinary(); err == nil {
					out = append(out, b)
				} else {
					fmt.Println(err)
					continue
				}
			}
		}
		rNext = r.NextRound()
		return
	}

	for id := range rounds {
		msgs1, nextR := a(nil, rounds[id])
		msgsOut1 = append(msgsOut1, msgs1...)
		rounds[id] = nextR.(frost.SignRound)
	}

	for id := range rounds {
		msgs2, nextR := a(msgsOut1, rounds[id])
		msgsOut2 = append(msgsOut2, msgs2...)
		rounds[id] = nextR.(frost.SignRound)
	}

	for id := range rounds {
		_, nextR := a(msgsOut2, rounds[id])
		rounds[id] = nextR.(frost.SignRound)
	}

	sig := rounds[1].WaitForSignOutput()
	sigBytes, err := sig.MarshalBinary()
	require.NoError(t, err)

	// validate using classic
	assert.True(t, ed25519.Verify(pkKey.ToEdDSA(), message, sigBytes))

	// Validate using our own function
	assert.True(t, sig.Verify(message, &pkKey))

	// Check all publicKeys return the same sig
	for _, id := range partyIDs {

		comparedSig := rounds[id].WaitForSignOutput()
		comparedSigBytes, _ := comparedSig.MarshalBinary()
		require.NoError(t, err)
		assert.True(t, bytes.Equal(sigBytes, comparedSigBytes))
	}

}

//func TestSingleParty(t *testing.T) {
//	_, skBytes, _ := ed25519.GenerateKey(rand.Reader)
//
//	sk, pk := eddsa.NewKeyPair(skBytes)
//
//	partyIDs := []uint32{1}
//	publicKeys := map[uint32]*eddsa.PublicKey{1: pk}
//
//	Message := []byte("hello")
//	round, _ := NewRound(1, publicKeys, partyIDs, &sk.Scalar, Message)
//
//	groupKey := round.(*base).Y
//
//	{
//		assert.Equal(t, 1, groupKey.Equal(&pk.Point))
//
//		l := polynomial.LagrangeCoefficient(1, partyIDs)
//		one := common.NewScalarUInt32(1)
//		assert.Equal(t, 1, l.Equal(one), "lagrange should be 1")
//	}
//	err := round.ProcessRound()
//	require.NoError(t, err)
//
//	// Round1
//	round = round.NextRound()
//	for _, m := range msgs {
//		err = round.StoreMessage(m)
//		require.NoError(t, err)
//	}
//	// msgs = [Sign1]
//	Rho := edwards25519.NewScalar()
//	//Ri := edwards25519.NewIdentityPoint()
//	idByte := []byte{0, 0, 0, 1}
//	D := new(edwards25519.Point)
//	E := new(edwards25519.Point)
//	e := new(edwards25519.Scalar)
//	d := new(edwards25519.Scalar)
//	{
//		d.Set(&round.(*round1).d)
//		e.Set(&round.(*round1).e)
//		D.ScalarBaseMult(d)
//		E.ScalarBaseMult(e)
//		assert.Equal(t, 1, msgs[0].Sign1.Di.Equal(D))
//		assert.Equal(t, 1, msgs[0].Sign1.Ei.Equal(E))
//	}
//	err = round.ProcessRound()
//	require.NoError(t, err)
//
//	//Round2
//	round = round.NextRound()
//	for _, m := range msgs {
//		err = round.StoreMessage(m)
//		require.NoError(t, err)
//	}
//	err = round.ProcessRound()
//	require.NoError(t, err)
//
//	{
//		B := make([]byte, 0, 4+32+32)
//		B = append(B, idByte...)
//		B = append(B, D.Bytes()...)
//		B = append(B, E.Bytes()...)
//
//		h := sha512.New()
//		h.Write([]byte("FROST-SHA512"))
//		h.Write(idByte)
//		h.Write(Message)
//		h.Write(B)
//		Rho.SetUniformBytes(h.Sum(nil))
//
//		assert.Equal(t, 1, Rho.Equal(&round.(*round2).Parties[1].Pi), "computed rho is not the same")
//
//		R := round.(*round2).R
//		Ri := round.(*round2).Parties[1].Ri
//		assert.Equal(t, 1, R.Equal(&Ri), "R and Ri should be the same")
//		assert.True(t, bytes.Equal(R.Bytes(), Ri.Bytes()))
//	}
//
//}

func generateFakeParties(t, n uint32) (*edwards25519.Scalar, []uint32, map[uint32]*eddsa.PublicKey, map[uint32]*edwards25519.Scalar) {
	allParties := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		allParties[i] = i + 1
	}

	secret := common.NewScalarRandom()
	poly := polynomial.NewPolynomial(t, secret)
	shares := poly.EvaluateMultiple(allParties)

	secrets := map[uint32]*edwards25519.Scalar{}
	parties := map[uint32]*eddsa.PublicKey{}

	for _, id := range allParties {
		secrets[id] = shares[id]
		parties[id] = &eddsa.PublicKey{Point: new(edwards25519.Point).ScalarBaseMult(shares[id])}
	}

	return secret, allParties, parties, secrets
}
