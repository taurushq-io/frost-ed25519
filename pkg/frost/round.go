package frost

type Round interface {
	StoreMessage(message []byte) error
	CanProcess() bool
	ProcessRound() ([][]byte, error)
	NextRound() Round
	Reset()
}

