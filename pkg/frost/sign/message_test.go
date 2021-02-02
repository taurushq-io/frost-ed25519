package sign

import (
	"bytes"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/tg-tss/pkg/helpers/common"
	"math/rand"
	"testing"
)

func TestMsg1_Encode_Decode(t *testing.T) {
	var d, e *edwards25519.Scalar
	var buf []byte
	var err error
	d = common.NewScalarRandom()
	e = common.NewScalarRandom()
	msg := Msg1{
		From: rand.Uint32(),
		CommitmentD: new(edwards25519.Point).ScalarBaseMult(d),
		CommitmentE: new(edwards25519.Point).ScalarBaseMult(e),
	}

	buf, err = msg.MarshalBinary()
	require.NoError(t, err, "failed to encode")


	msgDec := new(Msg1)
	err = msgDec.UnmarshalBinary(buf)
	require.NoError(t, err, "failed to decode")

	msgEnc, err := msgDec.MarshalBinary()
	require.NoError(t, err, "failed to encode again")

	require.True(t, bytes.Equal(msgEnc, buf))


	require.Equal(t, msg.From, msgDec.From, "from not decoded")
	require.Equal(t, 1, msg.CommitmentD.Equal(msgDec.CommitmentD), "D not same")
	require.Equal(t, 1, msg.CommitmentE.Equal(msgDec.CommitmentE), "E not same")
}

func TestMsg2_Encode_Decode(t *testing.T) {
	var s *edwards25519.Scalar
	var buf []byte
	var err error
	s = common.NewScalarRandom()
	msg := Msg2{
		From: rand.Uint32(),
		SignatureShare: s,
	}
	buf, err = msg.MarshalBinary()
	require.NoError(t, err, "failed to encode")


	msgDec := new(Msg2)
	err = msgDec.UnmarshalBinary(buf)
	require.NoError(t, err, "failed to decode")

	msgEnc, err := msgDec.MarshalBinary()
	require.NoError(t, err, "failed to encode again")

	require.True(t, bytes.Equal(msgEnc, buf))


	require.Equal(t, msg.From, msgDec.From, "from not decoded")
	require.Equal(t, 1, msg.SignatureShare.Equal(msgDec.SignatureShare), "S not same")
}
