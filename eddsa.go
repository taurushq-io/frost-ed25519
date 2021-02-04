package main

import (
	"filippo.io/edwards25519"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
)

func main() {
	var a, b edwards25519.Point
	c := common.NewScalarRandom()
	B := edwards25519.NewGeneratorPoint()
	a.Set(B)
	b.Set(B)

	a.ScalarMult(c, B)
	b.ScalarBaseMult(c)

	print(a.Equal(&b))
}
