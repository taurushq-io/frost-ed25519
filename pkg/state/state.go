package state

import (
	"errors"
	"sync"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type State struct {
	acceptedTypes    []messages.MessageType
	receivedMessages map[uint32]*messages.Message
	queue            []*messages.Message
	queueMtx         sync.Mutex

	timeout time.Duration
	timer   *time.Timer

	roundNumber int

	round rounds.Round

	output *BaseOutput

	*rounds.Parameters
}

func NewBaseState(params *rounds.Parameters, round rounds.Round, output *BaseOutput, timeout time.Duration) *State {
	s := &State{
		acceptedTypes:    append([]messages.MessageType{messages.MessageTypeNone}, round.AcceptedMessageTypes()...),
		receivedMessages: make(map[uint32]*messages.Message, params.N()),
		queue:            make([]*messages.Message, 0, params.N()),
		timer:            nil,
		roundNumber:      0,
		round:            round,
		output:           output,
		Parameters:       params,
	}

	for id := range params.OtherPartyIDsSet() {
		s.receivedMessages[id] = nil
	}

	if timeout > 0 {
		f := func() {
			s.Abort(rounds.NewError(0, errors.New("message timeout")))
		}
		s.timer = time.AfterFunc(timeout, f)
	}

	return s
}

// HandleMessage takes in an unmarshalled wire message and attempts to store it in the messages.Queue.
// It returns an error depending on whether the messages.Queue was able to store it.
func (s *State) HandleMessage(msg *messages.Message) error {
	if s.round == nil {
		return errors.New("already finished")
	}

	s.queueMtx.Lock()
	defer s.queueMtx.Unlock()

	if len(s.acceptedTypes) == 0 {
		return errors.New("no more messages being accepted")
	}

	senderID := msg.From

	// Ignore messages from self
	if senderID == s.SelfID() {
		return nil
	}
	// Ignore message not addressed to us
	if msg.To != 0 && msg.To != s.SelfID() {
		return nil
	}
	// Is the sender in our list of participants?
	if !s.IsParticipating(senderID) {
		return errors.New("sender is not a party")
	}

	// Check if we have already received a message from this party.
	// exists should never be false, but you never know
	if _, exists := s.receivedMessages[senderID]; exists {
		return errors.New("message from this party was already received")
	}

	if !s.isAcceptedType(msg.Type) {
		return errors.New("message type is not accepted for this type of round")
	}

	if s.timer != nil {
		s.timer.Reset(s.timeout)
	}

	if msg.Type == s.acceptedTypes[0] {
		s.receivedMessages[senderID] = msg
	} else {
		s.queue = append(s.queue, msg)
	}

	return nil
}

func (s *State) ProcessAll() []*messages.Message {
	s.queueMtx.Lock()
	defer s.queueMtx.Unlock()

	if len(s.receivedMessages) != s.N()-1 {
		return nil
	}

	for _, msg := range s.receivedMessages {
		if err := s.round.ProcessMessage(msg); err != nil {
			s.Abort(err)
			return nil
		}
	}

	for id := range s.receivedMessages {
		delete(s.receivedMessages, id)
	}

	newMessages, err := s.round.GenerateMessages()
	if err != nil {
		s.Abort(err)
		return nil
	}

	s.roundNumber++
	s.round = s.round.NextRound()

	s.acceptedTypes = s.acceptedTypes[1:]
	if len(s.acceptedTypes) > 0 {
		for _, msg := range s.queue {
			s.receivedMessages[msg.From] = msg
		}
	}

	return newMessages
}

func (s *State) Abort(err *rounds.Error) {
	if s.timer != nil {
		s.timer.Stop()
	}

	err.RoundNumber = s.roundNumber
	s.round.Reset()
	s.round = nil
}

func (s *State) isAcceptedType(msgType messages.MessageType) bool {
	for _, otherType := range s.acceptedTypes {
		if otherType == msgType {
			return true
		}
	}
	return false
}

// RoundNumber returns the current Round number
func (s *State) RoundNumber() int {
	return s.roundNumber
}
