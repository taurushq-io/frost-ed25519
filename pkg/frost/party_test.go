package frost

import (
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"github.com/taurusgroup/tg-tss/pkg/helpers/polynomial"
)

func TestComputeGroupKey(t *testing.T) {
	sk := common.NewScalarRandom()

	poly := polynomial.NewPolynomial(1, sk)

	T := uint32(10)
	parties := make(map[uint32]*Party, T+1)

	for i := uint32(1); i <= T+1; i++ {
		s := poly.Evaluate(i)
		p := &Party{
			Index:  i,
			Public: *edwards25519.NewIdentityPoint().ScalarBaseMult(s),
		}
		parties[i] = p
	}

	pk, err := ComputeGroupKey(parties)
	fmt.Println(pk.Point().Bytes())
	assert.NoError(t, err)
	pk2 := edwards25519.NewIdentityPoint().ScalarBaseMult(sk)
	assert.Equal(t, 1, pk.Point().Equal(pk2))
	//pk3 := edwards25519.NewIdentityPoint().Add(&p1.Public, &p2.Public)
	//assert.Equal(t, 1, pk.Point().Equal(pk3))
	//assert.Equal(t, 1, pk2.Equal(pk3))
}

func TestComputeLagrange(t *testing.T) {

	one := ComputeLagrange(0, nil)
	g := edwards25519.NewIdentityPoint().ScalarBaseMult(one)
	assert.Equal(t, 1, g.Equal(edwards25519.NewGeneratorPoint()))

	s := common.NewScalarRandom()
	p := edwards25519.NewIdentityPoint().ScalarBaseMult(s)
	p2 := edwards25519.NewIdentityPoint().ScalarMult(one, p)
	assert.Equal(t, 1, p.Equal(p2))
}
