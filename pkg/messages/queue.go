package messages

import (
	"errors"
	"sync"
)

var (
	ErrMessageTypeNotAccepted     = errors.New("message type is not accepted")
	ErrMessageFromSelf            = errors.New("message was from self")
	ErrMessageNotFromOtherParties = errors.New("sender is not a party")
	ErrWrongDestination           = errors.New("message is for other party")
)

type Queue struct {
	// queue holds all the messages that cannot be accepted for this current round.
	queue []*Message

	//
	acceptedTypes []MessageType

	// messages holds all messages received up to now for the current round
	messages map[uint32]*Message

	// otherPartyIDs is a set of parties without selfPartyID
	otherPartyIDs map[uint32]bool
	mtx           sync.Mutex

	selfPartyID uint32
	// currentType we are accepting
	currentType MessageType
}

// NewMessageQueue creates a new Queue for the protocol.
// acceptedTypes should by a slice of all messages that will be accepted, and in order.
// This helps Queue figure out which message can be accepted and at the right moment.
func NewMessageQueue(selfID uint32, otherPartyIDs map[uint32]bool, acceptedTypes []MessageType) (*Queue, error) {
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

	N := len(otherPartyIDs)

	m := Queue{
		messages:      make(map[uint32]*Message, N),
		queue:         make([]*Message, 0, N*len(acceptedTypes)),
		currentType:   acceptedTypes[0],
		acceptedTypes: acceptedTypes,
		otherPartyIDs: otherPartyIDs,
		selfPartyID:   selfID,
	}
	return &m, nil
}

// Store performs checks to make sure we can accept the given message.
// If the message is not for the current round, we store it in a queue.
// If it is, it goes into a map, with one message per party.
func (m *Queue) Store(message *Message) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.store(message)
}

func (m *Queue) store(message *Message) error {
	// Is the message one of those we accept
	if !m.isAcceptedType(message.Type) {
		return ErrMessageTypeNotAccepted
	}

	// Is the message from someone else than us
	if message.From == m.selfPartyID {
		return ErrMessageFromSelf
	}

	// Is the sender in our list of participants?
	if _, ok := m.otherPartyIDs[message.From]; !ok {
		return ErrMessageNotFromOtherParties
	}

	// If the message has a set destination, we check that it is for us
	if message.To != 0 && message.To != m.selfPartyID {
		return ErrWrongDestination
	}

	// The message is the one we are currently accepting
	if message.Type == m.currentType {
		m.messages[message.From] = message
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

	if len(m.messages) == len(m.otherPartyIDs) {
		for id := range m.otherPartyIDs {
			if _, ok := m.messages[id]; !ok {
				return false
			}
		}
		return true
	}

	return false
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
	for id := range m.messages {
		delete(m.messages, id)
	}

	// remove the current message type from the accepted list
	m.acceptedTypes = m.acceptedTypes[1:]

	if !m.isAcceptedType(m.currentType + 1) {
		return
	}

	m.currentType++
	m.extractFromQueue()
}

func (m *Queue) isAcceptedType(msgType MessageType) bool {
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
func (m *Queue) Messages() map[uint32]*Message {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.receivedAll() {
		return m.messages
	}
	return nil
}

// extractFromQueue goes over the queue and adds messages for the current round to the map.
func (m *Queue) extractFromQueue() {
	var msg *Message
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
