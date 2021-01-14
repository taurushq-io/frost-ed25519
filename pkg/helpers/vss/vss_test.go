package vss

import (
	"filippo.io/edwards25519"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"testing"
)

func TestSumVSS(t *testing.T) {
	parties := []common.Party{common.Party(1), common.Party(4), common.Party(100)}
	thresh := uint32(1)
	n := uint32(len(parties))
	secrets := make([]*edwards25519.Scalar, n)
	vss := make(map[common.Party]*VSS)
	finalShares := make(Shares)

	for _, party := range parties {
		finalShares[party] = edwards25519.NewScalar()
	}

	var err error
	var shares Shares
	for i, p := range parties {
		secrets[i], err = common.NewScalarRandom()
		require.NoError(t, err)

		vss[p], shares, err = NewVSS(thresh, secrets[i], parties)
		require.NoError(t, err)

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
