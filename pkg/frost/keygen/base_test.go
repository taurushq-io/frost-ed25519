package keygen

import (
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

func TestKeygen(t *testing.T) {
	N := uint32(10)
	T := N / 2

	partyIDs := make([]uint32, 0, N)
	for id := uint32(1); id <= N; id++ {
		partyIDs = append(partyIDs, id)
	}

	Rounds := make(map[uint32]rounds.KeyGenRound)

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N*(N-1)/2)

	for _, id := range partyIDs {
		r0, _ := NewRound(id, T, partyIDs)
		Rounds[id] = r0.(*round0)
	}

	doRound := func(in [][]byte, r rounds.Round) (out [][]byte, rNext rounds.Round) {
		out = make([][]byte, 0, N-1)
		for _, m := range in {
			msgTmp := messages.Message{}
			err := msgTmp.UnmarshalBinary(m)
			assert.NoError(t, err, "failed to store message")

			assert.NoError(t, r.StoreMessage(&msgTmp), "failed to store message")
		}

		r.ProcessMessages()
		r.ProcessRound()
		for _, msgOut := range r.GenerateMessages() {
			if b, err := msgOut.MarshalBinary(); err == nil {
				out = append(out, b)
			} else {
				fmt.Println(err)
				return
			}
		}
		return out, r.NextRound()
	}

	for id, r0 := range Rounds {
		msgs1, nextR := doRound(nil, r0)
		msgsOut1 = append(msgsOut1, msgs1...)
		Rounds[id] = nextR.(rounds.KeyGenRound)
	}

	for id, r1 := range Rounds {
		msgs2, nextR := doRound(msgsOut1, r1)
		msgsOut2 = append(msgsOut2, msgs2...)
		Rounds[id] = nextR.(rounds.KeyGenRound)
	}

	for id := range Rounds {
		doRound(msgsOut2, Rounds[id])
	}
	var tmp, pk edwards25519.Point
	var sk edwards25519.Scalar

	allPartyIDs := make([]uint32, 0, N)
	for id := uint32(1); id <= N; id++ {
		allPartyIDs = append(allPartyIDs, id)
	}

	sk.Set(edwards25519.NewScalar())
	pk.Set(edwards25519.NewIdentityPoint())

	groupKey, publicShares, _, err := Rounds[1].WaitForKeygenOutput()
	assert.NoError(t, err, "failed to get output")
	for id, round := range Rounds {
		groupKeyCmp, publicSharesCmp, secretCmp, err := round.WaitForKeygenOutput()
		assert.NoError(t, err, "failed to get output")

		for id2, share := range publicSharesCmp {
			assert.True(t, publicShares[id2].Equal(share))
		}
		assert.Equal(t, 1, tmp.ScalarBaseMult(secretCmp.Scalar()).Equal(publicShares[id].Point()))
		assert.True(t, groupKeyCmp.Equal(groupKey))

		lagrange := polynomial.LagrangeCoefficient(id, allPartyIDs)
		lagrange.Multiply(lagrange, secretCmp.Scalar())
		sk.Add(&sk, lagrange)
		tmp.ScalarBaseMult(lagrange)
		pk.Add(&pk, &tmp)
	}

	assert.Equal(t, 1, groupKey.Point().Equal(&pk))
}
