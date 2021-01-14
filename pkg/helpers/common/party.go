package common


type Party uint32

func (p Party) Bytes() []byte {
	i := uint32(p)
	return []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
}

func (p Party) UInt32() uint32 {
	return uint32(p)
}

func (p Party) Int64() int64 {
	return int64(p)
}


//type (
//	PublicKeyShare struct {
//		Party     Party
//		PublicKey curve.ECPoint
//	}
//)
