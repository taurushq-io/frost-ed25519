package sign

type (


	Msg1 struct {
		// CommitmentD and CommitmentE are edwards25519.Point encoded with .... TODO
		CommitmentD, CommitmentE []byte
	}

	Msg2 struct {
		// SignatureShare is a edwards25519.Scalar.
		// It represents the sender's share of the 's' part of the final signature
		SignatureShare []byte
	}
	Message struct {
		Msg1 *Msg1
		Msg2 *Msg2
	}
)

type MessageType uint8
const (
	MessageTypeSign1 MessageType = iota
	MessageTypeSign2
	MessageTypeSignature
)
