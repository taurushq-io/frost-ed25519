package scalar

import "encoding"

type FROSTMarshaller interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	BytesAppend(existing []byte) (data []byte, err error)
	Size() int
}
