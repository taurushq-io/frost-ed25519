package common

import "github.com/taurusgroup/tg-tss/pkg/helpers/curve"

type Party = uint32

func BytesFromUInt32(i uint32) []byte {
	return []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
}

type (
	PublicKeyShare struct {
		Party     Party
		PublicKey curve.ECPoint
	}
)
