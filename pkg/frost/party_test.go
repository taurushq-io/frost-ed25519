package frost

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"testing"
)

func TestComputeGroupKey(t *testing.T) {
	s1, _ := common.NewScalarRandom()
	s2, _ := common.NewScalarRandom()
	p1 := &Party{
		Index:  1,
		Public: new(edwards25519.Point).ScalarBaseMult(s1),
	}
	p2 := &Party{
		Index:  2,
		Public: new(edwards25519.Point).ScalarBaseMult(s2),
	}
	parties := map[uint32]*Party{1: p1, 2: p2}

	sk := edwards25519.NewScalar()
	sk.Add(s1, s2)
	pk, err := ComputeGroupKey(parties)
	assert.NoError(t, err)
	pk2 := new(edwards25519.Point).ScalarBaseMult(sk)
	assert.Equal(t, 1, pk.Equal(pk2))
	pk3 := new(edwards25519.Point).Add(p1.Public, p2.Public)
	assert.Equal(t, 1, pk.Equal(pk3))
	assert.Equal(t, 1, pk2.Equal(pk3))

}

func TestComputeLagrange(t *testing.T) {

	one, _ := ComputeLagrange(0, nil)
	g := new(edwards25519.Point).ScalarBaseMult(one)
	assert.Equal(t, 1, g.Equal(edwards25519.NewGeneratorPoint()))

	s, _ := common.NewScalarRandom()
	p := new(edwards25519.Point).ScalarBaseMult(s)
	p2 := new(edwards25519.Point).ScalarMult(one, p)
	assert.Equal(t, 1, p.Equal(p2))
}
