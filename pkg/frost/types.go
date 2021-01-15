package frost

type Round interface {
	ProcessMessage(msg *Message)
}

type (
	KeyGenMessage struct {
		Message1 *KeyGenMessage1
		Message2 *KeyGenMessage2
	}

	SignMessage struct {
		Message1 *SignMessage1
		Message2 *SignMessage2
	}

	Message struct {
		KeyGen *KeyGenMessage
		Sign *SignMessage
	}
)

