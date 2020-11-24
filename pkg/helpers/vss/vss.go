package vss

import "math/big"

type (
	Share struct {
		partyId int
		share   *big.Int
	}

	Commitment struct {
		partyId int
		share   *big.Int
	}

	VSSShares      []Share
	VSSCommitments []Commitment
)
