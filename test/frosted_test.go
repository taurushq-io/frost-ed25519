package main

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/communication"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func FakeKeygen(partyIDs []uint32) (*eddsa.Shares, map[uint32]*eddsa.PrivateKey) {
	n := len(partyIDs)
	shares := make(map[uint32]*edwards25519.Point, n)
	secrets := make(map[uint32]*eddsa.PrivateKey, n)
	for _, id := range partyIDs {
		var pk edwards25519.Point
		sk := scalar.NewScalarRandom()
		secrets[id] = eddsa.NewPrivateKeyFromScalar(sk)
		shares[id] = pk.ScalarBaseMult(sk)
	}
	return eddsa.NewShares(shares, uint32(n-1), nil), secrets
}

func TestSetup(t *testing.T) {
	N := uint32(100)
	message, _, signIDs := Setup(N, N-1)
	shares, secrets := FakeKeygen(signIDs)

	signComm := communication.NewChannelCommunicatorMap(signIDs)

	err := DoSign(N-1, signIDs, shares, secrets, signComm, message)
	if err != nil {
		t.Error(err)
	}
}
