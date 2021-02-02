package vss

import (
	"filippo.io/edwards25519"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"testing"
)

func TestSumVSS(t *testing.T) {
	parties := []uint32{1, 4, 100}
	thresh := uint32(1)
	n := uint32(len(parties))
	secrets := make([]*edwards25519.Scalar, n)
	vss := make(map[uint32]*VSS)
	finalShares := make(Shares)

	for _, party := range parties {
		finalShares[party] = edwards25519.NewScalar()
	}

	var err error
	var shares Shares
	for i, p := range parties {
		secrets[i] = common.NewScalarRandom()

		vss[p], shares = NewVSS(thresh, secrets[i], parties)

		for _, otherParty := range parties {
			fmt.Println(otherParty)
			require.True(t, vss[p].VerifyShare(shares[otherParty], otherParty))

			finalShares[otherParty].Add(finalShares[otherParty], shares[otherParty])
		}
	}

	var vssSum *VSS
	vssSum, err = SumVSS(vss, thresh, n)
	require.NoError(t, err)

	for party, share := range finalShares {
		require.True(t, vssSum.VerifyShare(share, party))
	}
}
