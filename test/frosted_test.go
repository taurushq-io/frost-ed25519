package main

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/communication"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

func FakeKeygen(partyIDs []party.ID) (*eddsa.Shares, map[party.ID]*eddsa.PrivateKey) {
	n := party.Size(len(partyIDs))
	shares := make(map[party.ID]*edwards25519.Point, n)
	secrets := make(map[party.ID]*eddsa.PrivateKey, n)
	for _, id := range partyIDs {
		var pk edwards25519.Point
		sk := scalar.NewScalarRandom()
		secrets[id] = eddsa.NewPrivateKeyFromScalar(sk)
		shares[id] = pk.ScalarBaseMult(sk)
	}
	return eddsa.NewShares(shares, n-1, nil), secrets
}

func TestSetup(t *testing.T) {
	N := party.Size(10)
	message, _, signIDs := Setup(N, N-1)
	shares, secrets := FakeKeygen(signIDs)

	signComm := communication.NewChannelCommunicatorMap(signIDs)

	err := DoSign(N-1, signIDs, shares, secrets, signComm, message)
	if err != nil {
		t.Error(err)
	}
}
