package keygen

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
)

func TestKeygen(t *testing.T) {
	N := uint32(20)
	T := uint32(10)

	partyIDs := make([]uint32, 0, N+5)
	for id := uint32(1); id <= N; id++ {
		partyIDs = append(partyIDs, id)
	}
	for i := len(partyIDs); i < cap(partyIDs); i++ {
		partyIDs = append(partyIDs, uint32(i)+3-N)
	}

	rounds0 := make(map[uint32]*base)
	rounds1 := make(map[uint32]*round1)
	rounds2 := make(map[uint32]*round2)

	msgsOut1 := make([][]byte, 0, N*(N-1))
	msgsOut2 := make([][]byte, 0, N*(N-1))

	for _, id := range partyIDs {
		r0, _ := NewRound(id, T, partyIDs)
		rounds0[id] = r0.(*base)
	}

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
			assert.NoError(t, err, "failed to process")
			err = r.ProcessRound()

			msgsOut, err := r.GenerateMessages()
			assert.NoError(t, err, "failed to process")
			rNext = r.NextRound()
			for _, msgOut := range msgsOut {
				if b, err := msgOut.MarshalBinary(); err == nil {
					out = append(out, b)
				} else {
					return
				}
			}
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
	println("done round 0")

	for id, r1 := range rounds1 {
		msgs2, nextR := a(msgsOut1, r1)
		for _, m := range msgs2 {
			msgsOut2 = append(msgsOut2, m)
		}
		rounds2[id] = nextR.(*round2)
	}
	println("done round 1")

	for _, r2 := range rounds2 {
		a(msgsOut2, r2)
	}

	var tmp, pk edwards25519.Point
	var sk edwards25519.Scalar

	allPartyIDs := make([]uint32, 0, N)
	for id := uint32(1); id <= N; id++ {
		allPartyIDs = append(allPartyIDs, id)
	}

	sk.Set(edwards25519.NewScalar())
	pk.Set(edwards25519.NewIdentityPoint())

	groupKey, publicShares, _, err := rounds2[1].WaitForKeyGenOutput()
	assert.NoError(t, err, "failed to get output")
	for id, round := range rounds2 {
		groupKeyCmp, publicSharesCmp, secretCmp, err := round.WaitForKeyGenOutput()
		assert.NoError(t, err, "failed to get output")

		for id2, share := range publicSharesCmp {
			assert.Equal(t, 1, publicShares[id2].Equal(share.Point))
		}
		assert.Equal(t, 1, tmp.ScalarBaseMult(&secretCmp).Equal(publicShares[id].Point))
		assert.Equal(t, 1, groupKeyCmp.Equal(groupKey.Point))

		lagrange := polynomial.LagrangeCoefficient(id, allPartyIDs)
		lagrange.Multiply(lagrange, &secretCmp)
		sk.Add(&sk, lagrange)
		tmp.ScalarBaseMult(lagrange)
		pk.Add(&pk, &tmp)
	}

	assert.Equal(t, 1, groupKey.Equal(&pk))

}
