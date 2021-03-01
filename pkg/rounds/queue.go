package rounds

import (
	"errors"
	"sync"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type Queue struct {
	expectedMessages int

	// queue holds all the messages that cannot be accepted for this current round.
	queue []*messages.Message

	// is the list of types we can accept
	acceptedTypes []messages.MessageType

	// currentMessages holds all messages received up to now for the current round
	currentMessages map[uint32]*messages.Message

	// currentType we are accepting
	currentType messages.MessageType

	mtx sync.Mutex
}

// NewMessageQueue creates a new Queue for the protocol.
// acceptedTypes should by a slice of all messages that will be accepted, and in order.
// This helps Queue figure out which message can be accepted and at the right moment.
func NewMessageQueue(acceptedTypes []messages.MessageType, n int) (*Queue, error) {
	// Make sure the types are sorted.
	// We assume the types are in increasing order
	for i := range acceptedTypes {
		if i >= 1 {
			if acceptedTypes[i] == acceptedTypes[i-1] {
				return nil, errors.New("acceptedTypes contains duplicate")
			}

			if acceptedTypes[i] != acceptedTypes[i-1]+1 {
				return nil, errors.New("acceptedTypes is not in order")
			}
		}
	}

	m := Queue{
		expectedMessages: n,
		currentMessages:  make(map[uint32]*messages.Message, n),
		queue:            make([]*messages.Message, 0, n*len(acceptedTypes)),
		currentType:      acceptedTypes[0],
		acceptedTypes:    acceptedTypes,
	}
	return &m, nil
}

// Store performs checks to make sure we can accept the given message.
// If the message is not for the current round, we store it in a queue.
// If it is, it goes into a map, with one message per party.
func (m *Queue) Store(message *messages.Message) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.store(message)
}

func (m *Queue) store(message *messages.Message) error {
	// Is the message one of those we accept
	if !m.isAcceptedType(message.Type) {
		return errors.New("message type is not accepted")
	}

	// The message is the one we are currently accepting
	if message.Type == m.currentType {
		m.currentMessages[message.From] = message
		return nil
	}

	// This is a future message that we store for later
	if message.Type > m.currentType {
		m.queue = append(m.queue, message)
		return nil
	}

	return nil
}

// ReceivedAll indicates whether we have received a message from all parties for this round.
// It also transfers any messages from the queue into the map
func (m *Queue) ReceivedAll() bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return m.receivedAll()
}

func (m *Queue) receivedAll() bool {
	m.extractFromQueue()

	return len(m.currentMessages) == m.expectedMessages-1
}

// NextRound should be called when a round is transitioning.
// We clear the map of received messages, process the queue,
// and update the current receiving type.
func (m *Queue) NextRound() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if !m.receivedAll() {
		return
	}

	// Delete all messages for the round
	for id := range m.currentMessages {
		delete(m.currentMessages, id)
	}

	// remove the current message type from the accepted list
	m.acceptedTypes = m.acceptedTypes[1:]

	if !m.isAcceptedType(m.currentType + 1) {
		return
	}

	m.currentType++
	m.extractFromQueue()
}

func (m *Queue) isAcceptedType(msgType messages.MessageType) bool {
	for _, otherType := range m.acceptedTypes {
		if otherType == msgType {
			return true
		}
	}
	return false
}

// Messages returns a map of messages for the current round.
// There is one message per party which is why it is a map.
// If not all messages have been received, we return nothing.
func (m *Queue) Messages() map[uint32]*messages.Message {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.receivedAll() {
		return m.currentMessages
	}
	return nil
}

// extractFromQueue goes over the queue and adds messages for the current round to the map.
func (m *Queue) extractFromQueue() {
	var msg *messages.Message
	b := m.queue[:0]
	for i := 0; i < len(m.queue); i++ {
		msg = m.queue[i]

		// msg is for the current round
		if msg.Type == m.currentType {
			if err := m.store(msg); err != nil {
				panic(err)
			}
		} else {
			b = append(b, msg)
		}
	}
	m.queue = b
}
