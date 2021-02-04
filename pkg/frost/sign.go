package frost

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

type (
	SignParameters struct {
		OtherPartyIDs []common.Party
		SelfPartyID   common.Party
		PublicKeys    []*edwards25519.Point
	}

	SignRound1 struct {
		// ID
		d, e                       *edwards25519.Scalar
		dCommitments, eCommitments map[common.Party]*edwards25519.Point
	}
	// SignMessage1 must be broadcast
	SignMessage1 struct {
		// need unique session ID
		dCommitment, eCommitment *edwards25519.Point
	}

	SignRound2 struct {
		*SignRound1

		rhos              map[common.Party]*edwards25519.Scalar // rho_l
		nonce             *edwards25519.Point                   // R= ∑D + rho•E
		challenge         *edwards25519.Scalar                  // c = H(R,pk,m)  or H(R,A,M) from Ed25519
		partialSignatures map[common.Party]*edwards25519.Scalar // z = d + (e rho) + lambda x c
	}
	SignMessage2 struct {
		partialSignature *edwards25519.Scalar
	}
)
