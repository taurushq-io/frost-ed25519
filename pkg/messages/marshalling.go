package messages

import (
	"bytes"
	"encoding"
	"errors"
)

type FROSTMarshaller interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	BytesAppend(existing []byte) (data []byte, err error)
	Size() int
}

func CheckFROSTMarshaller(input, output FROSTMarshaller) error {
	var err error
	var firstData, secondData, thirdData []byte
	firstData, err = input.MarshalBinary()
	if err != nil {
		return errors.New("failed to marshall struct")
	}

	err = output.UnmarshalBinary(firstData)
	if err != nil {
		return errors.New("failed to unmarshall data")
	}

	secondData, err = output.MarshalBinary()
	if err != nil {
		return errors.New("failed to marshall struct of unmarshalled struct")
	}

	if !bytes.Equal(firstData, secondData) {
		return errors.New("both byte outputs should be the same")
	}

	if input.Size() != len(firstData) {
		return errors.New("reported size should be consistent")
	}

	thirdData, err = input.BytesAppend(nil)
	if err != nil {
		return errors.New("failed to marshall struct")
	}

	if !bytes.Equal(firstData, thirdData) {
		return errors.New("both byte outputs should be the same")
	}
	return nil
}
