package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/frost"
	"github.com/taurusgroup/tg-tss/pkg/frost/messages"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

func TestRound(t *testing.T) {
	N := uint32(10)
	T := uint32(9)

	_, AllPartyIDs, parties, secrets := generateFakeParties(T, N)

	partyIDs := AllPartyIDs[:T+1]

	rounds0 := make(map[uint32]*round0)
	rounds1 := make(map[uint32]*round1)
	rounds2 := make(map[uint32]*round2)

	msgsOut1 := make([]*messages.Message, 0, N)
	msgsOut2 := make([]*messages.Message, 0, N)
	msgsOut3 := make([]*messages.Message, 0, N)

	message := []byte("hello")

	for _, id := range partyIDs {
		r0, _ := NewRound(id, parties, partyIDs, secrets[id], message)
		rounds0[id] = r0.(*round0)
	}

	rTmp := rounds0[1]
	pkKey := *rTmp.Y

	a := func(in []*messages.Message, r frost.Round) (out []*messages.Message, rNext frost.Round) {
		var err error
		var msgsOut []*messages.Message
		out = make([]*messages.Message, 0, T+1)
		for _, m := range in {
			assert.NoError(t, r.StoreMessage(m), "failed to store message")
		}
		if r.CanProcess() {
			msgsOut, err = r.ProcessRound()
			assert.NoError(t, err, "failed to process")

			for _, msgOut := range msgsOut {
				out = append(out, msgOut)
			}
			rNext = r.NextRound()
		}
		return
	}

	for id, r0 := range rounds0 {
		msgs1, nextR := a(nil, r0)
		for _, m := range msgs1 {
			msgsOut1 = append(msgsOut1, m)
		}
		rounds1[id] = nextR.(*round1)
	}

	for id, r1 := range rounds1 {
		msgs2, nextR := a(msgsOut1, r1)
		for _, m := range msgs2 {
			msgsOut2 = append(msgsOut2, m)
		}
		rounds2[id] = nextR.(*round2)
	}

	for _, r2 := range rounds2 {
		msgs3, _ := a(msgsOut2, r2)
		for _, m := range msgs3 {
			msgsOut3 = append(msgsOut3, m)
		}
	}

	baseSig := msgsOut3[0].Sign3.Sig

	// validate using classic
	assert.True(t, ed25519.Verify(pkKey.ToEdDSA(), message, baseSig[:]))

	// Validate using our own function
	r, err := new(edwards25519.Point).SetBytes(baseSig[:32])
	require.NoError(t, err)
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(baseSig[32:])
	require.NoError(t, err)
	sig := frost.Signature{
		R: *r,
		S: *s,
	}
	assert.True(t, sig.Verify(message, &pkKey))

	// Check all parties return the same sig
	for _, m := range msgsOut3 {
		assert.True(t, bytes.Equal(baseSig[:], m.Sign3.Sig[:]))
	}

}

func TestSingleParty(t *testing.T) {
	_, skBytes, _ := ed25519.GenerateKey(rand.Reader)

	sk := frost.NewPrivateKey(skBytes)
	pk := sk.PublicKey()
	p := frost.Party{
		Index:  1,
		Public: *pk.Point(),
	}

	s := frost.PartySecret{
		Index:  1,
		Secret: *sk.Scalar(),
	}

	partyIDs := []uint32{1}
	parties := map[uint32]*frost.Party{1: &p}

	Message := []byte("hello")
	round, _ := NewRound(1, parties, partyIDs, &s, Message)

	groupKey := round.(*round0).Y
	key := groupKey.Point()

	{
		assert.Equal(t, 1, key.Equal(pk.Point()))

		l := frost.ComputeLagrange(1, partyIDs)
		one := common.NewScalarUInt32(1)
		assert.Equal(t, 1, l.Equal(one), "lagrange should be 1")
	}
	msgs, err := round.ProcessRound()
	require.NoError(t, err)

	// Round1
	round = round.NextRound()
	for _, m := range msgs {
		err = round.StoreMessage(m)
		require.NoError(t, err)
	}
	// msgs = [Sign1]
	Rho := edwards25519.NewScalar()
	//Ri := edwards25519.NewIdentityPoint()
	idByte := []byte{0, 0, 0, 1}
	D := new(edwards25519.Point)
	E := new(edwards25519.Point)
	e := new(edwards25519.Scalar)
	d := new(edwards25519.Scalar)
	{
		d.Set(&round.(*round1).d)
		e.Set(&round.(*round1).e)
		D.ScalarBaseMult(d)
		E.ScalarBaseMult(e)
		assert.Equal(t, 1, msgs[0].Sign1.Di.Equal(D))
		assert.Equal(t, 1, msgs[0].Sign1.Ei.Equal(E))
	}
	msgs, err = round.ProcessRound()
	require.NoError(t, err)

	//Round2
	round = round.NextRound()
	for _, m := range msgs {
		err = round.StoreMessage(m)
		require.NoError(t, err)
	}
	msgs, err = round.ProcessRound()
	require.NoError(t, err)

	{
		B := make([]byte, 0, 4+32+32)
		B = append(B, idByte...)
		B = append(B, D.Bytes()...)
		B = append(B, E.Bytes()...)
		fmt.Println(B)

		h := sha512.New()
		h.Write([]byte("FROST-SHA512"))
		h.Write(idByte)
		h.Write(Message)
		h.Write(B)
		Rho.SetUniformBytes(h.Sum(nil))

		assert.Equal(t, 1, Rho.Equal(&round.(*round2).Parties[1].Pi), "computed rho is not the same")

		R := round.(*round2).R
		Ri := round.(*round2).Parties[1].Ri
		assert.Equal(t, 1, R.Equal(&Ri), "R and Ri should be the same")
		assert.True(t, bytes.Equal(R.Bytes(), Ri.Bytes()))
	}

}
