package messages

import (
	"bytes"
	"encoding"
	"errors"
)

type FROSTMarshaler interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	// BytesAppend is the same as BinaryMarshall but allows the caller to perform the allocation
	BytesAppend(existing []byte) (data []byte, err error)
	// Size should return the number of bytes used to store the type.
	Size() int

	// Equal is used mostly for testing and returns true if other represents the same value as the receiver.
	Equal(other interface{}) bool
}

// CheckFROSTMarshaler provides some basic tests to make sure the interface is properly implemented.
// Should be used for tests of message types.
func CheckFROSTMarshaler(input, output FROSTMarshaler) error {
	var err error
	var firstData, secondData, thirdData []byte

	// Encode a first time
	firstData, err = input.MarshalBinary()
	if err != nil {
		return errors.New("failed to marshall struct")
	}

	// Decode it
	err = output.UnmarshalBinary(firstData)
	if err != nil {
		return errors.New("failed to unmarshall data")
	}

	// If we encode the decoded data, we should be getting the same result.
	// This would only fail if the Marshal step is wrong.
	secondData, err = output.MarshalBinary()
	if err != nil {
		return errors.New("failed to marshall struct of unmarshalled struct")
	}

	if !bytes.Equal(firstData, secondData) {
		return errors.New("both byte outputs should be the same")
	}

	// Verify that .Size reports the right result
	if input.Size() != len(firstData) {
		return errors.New("reported size should be consistent")
	}

	// Also check that BytesAppend gives the same result
	thirdData, err = input.BytesAppend(nil)
	if err != nil {
		return errors.New("failed to marshall struct")
	}

	if !bytes.Equal(firstData, thirdData) {
		return errors.New("both byte outputs should be the same")
	}
	return nil
}
