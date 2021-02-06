package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
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

	rounds0 := make(map[uint32]*base)
	rounds1 := make(map[uint32]*round1)
	rounds2 := make(map[uint32]*round2)

	msgsOut1 := make([]*messages.Message, 0, N)
	msgsOut2 := make([]*messages.Message, 0, N)
	msgsOut3 := make([]*messages.Message, 0, N)

	message := []byte("hello")

	for _, id := range partyIDs {
		r0, _ := NewRound(id, publicKeys, partyIDs, secrets[id], message)
		rounds0[id] = r0.(*base)
	}

	rTmp := rounds0[1]
	pk := rTmp.Y
	pkKey := eddsa.PublicKey{Point: pk}

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

	sig := msgsOut3[0].SignOutput.Signature
	sigBytes, err := sig.MarshalBinary()
	require.NoError(t, err)

	// validate using classic
	assert.True(t, ed25519.Verify(pkKey.ToEdDSA(), message, sigBytes))

	// Validate using our own function
	assert.True(t, sig.Verify(message, &pkKey))

	// Check all publicKeys return the same sig
	for _, m := range msgsOut3 {
		comparedSig, err := m.SignOutput.Signature.MarshalBinary()
		require.NoError(t, err)
		assert.True(t, bytes.Equal(sigBytes, comparedSig))
	}

}

func TestSingleParty(t *testing.T) {
	_, skBytes, _ := ed25519.GenerateKey(rand.Reader)

	sk := eddsa.NewPrivateKey(skBytes)
	pk := sk.PublicKey()

	partyIDs := []uint32{1}
	publicKeys := map[uint32]*eddsa.PublicKey{1: pk}

	Message := []byte("hello")
	round, _ := NewRound(1, publicKeys, partyIDs, &sk.Scalar, Message)

	groupKey := round.(*base).Y

	{
		assert.Equal(t, 1, groupKey.Equal(&pk.Point))

		l := polynomial.LagrangeCoefficient(1, partyIDs)
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

	var pk edwards25519.Point
	for _, id := range allParties {
		secrets[id] = shares[id]
		pk.ScalarBaseMult(shares[id])
		parties[id] = &eddsa.PublicKey{Point: pk}
	}

	return secret, allParties, parties, secrets
}
