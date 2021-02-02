package keygen

import "github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"

type KeyGenerator struct {
	Index uint32

	CommitmentPolynomial *polynomial.Exponent
}
