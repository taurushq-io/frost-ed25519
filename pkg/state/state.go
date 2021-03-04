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

	doneChan chan struct{}
	done     bool
	err      *rounds.Error
	mtx      sync.Mutex

	params *rounds.Parameters
}

func NewBaseState(params *rounds.Parameters, round rounds.Round, timeout time.Duration) *State {
	s := &State{
		acceptedTypes:    append([]messages.MessageType{messages.MessageTypeNone}, round.AcceptedMessageTypes()...),
		receivedMessages: make(map[uint32]*messages.Message, params.N()),
		queue:            make([]*messages.Message, 0, params.N()),
		timeout:          timeout,
		round:            round,
		doneChan:         make(chan struct{}),
		params:           params,
	}

	for id := range params.OtherPartyIDsSet() {
		s.receivedMessages[id] = nil
	}

	if timeout > 0 {
		f := func() {
			s.reportError(rounds.NewError(0, errors.New("message timeout")))
		}
		s.timer = time.AfterFunc(timeout, f)
	}

	return s
}

// HandleMessage takes in an unmarshalled wire message and attempts to store it in the messages.Queue.
// It returns an error depending on whether the messages.Queue was able to store it.
func (s *State) HandleMessage(msg *messages.Message) error {
	if s.IsFinished() {
		return errors.New("already finished")
	}

	s.queueMtx.Lock()
	defer s.queueMtx.Unlock()

	if len(s.acceptedTypes) == 0 {
		return errors.New("no more messages being accepted")
	}

	senderID := msg.From

	// Ignore messages from self
	if senderID == s.params.SelfID() {
		return nil
	}
	// Ignore message not addressed to us
	if msg.To != 0 && msg.To != s.params.SelfID() {
		return nil
	}
	// Is the sender in our list of participants?
	if !s.params.IsParticipating(senderID) {
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
		if !s.timer.Stop() {
			<-s.timer.C
		}
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
	if s.IsFinished() {
		return nil
	}
	s.queueMtx.Lock()
	defer s.queueMtx.Unlock()

	// Only continue if we received messages from all
	if len(s.receivedMessages) != s.params.N()-1 {
		return nil
	}

	for _, msg := range s.receivedMessages {
		if err := s.round.ProcessMessage(msg); err != nil {
			s.reportError(err)
			return nil
		}
	}

	for id := range s.receivedMessages {
		delete(s.receivedMessages, id)
	}

	newMessages, err := s.round.GenerateMessages()
	if err != nil {
		s.reportError(err)
		return nil
	}

	s.roundNumber++

	s.acceptedTypes = s.acceptedTypes[1:]
	if len(s.acceptedTypes) > 0 {
		for _, msg := range s.queue {
			s.receivedMessages[msg.From] = msg
		}
	}

	nextRound := s.round.NextRound()

	// We are finished
	if nextRound == nil {
		s.finish()
	} else {
		s.round = nextRound
	}

	return newMessages
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

//
// Output
//

func (s *State) finish() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.done = true

	s.round.Reset()
	if s.timer != nil {
		if !s.timer.Stop() {
			<-s.timer.C
		}
	}
	close(s.doneChan)
}

func (s *State) reportError(err *rounds.Error) {
	if s.done {
		return
	}

	// We already got an error
	// TODO chain the errors
	if s.err == nil {
		err.RoundNumber = s.roundNumber
		s.err = err
	}

	s.finish()
}

func (s *State) IsFinished() bool {
	return s.done
}

func (s *State) WaitForError() *rounds.Error {
	if !s.done {
		<-s.doneChan
	}
	return s.err
}
