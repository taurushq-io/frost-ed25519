package state

import (
	"errors"
	"sync"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/rounds"
)

type State struct {
	acceptedTypes    []messages.MessageType
	receivedMessages map[party.ID]*messages.Message
	queue            []*messages.Message

	timer

	roundNumber int

	round rounds.Round

	doneChan chan struct{}
	done     bool
	err      *rounds.Error

	params *rounds.Parameters

	mtx sync.Mutex
}

func NewBaseState(params *rounds.Parameters, round rounds.Round, timeout time.Duration) *State {
	s := &State{
		acceptedTypes:    append([]messages.MessageType{messages.MessageTypeNone}, round.AcceptedMessageTypes()...),
		receivedMessages: make(map[party.ID]*messages.Message, params.N()),
		queue:            make([]*messages.Message, 0, params.N()),
		round:            round,
		doneChan:         make(chan struct{}),
		params:           params,
	}

	s.timer = newTimer(timeout, func() {
		s.mtx.Lock()
		s.reportError(rounds.NewError(0, errors.New("message timeout")))
		s.mtx.Unlock()
	})

	for id := range params.OtherPartyIDsSet() {
		s.receivedMessages[id] = nil
	}

	return s
}

// HandleMessage should be called on an unmarshalled messages.Message appropriate for the protocol execution.
// It performs basic checks to see whether the message can be used.
// - Is the protocol already done
// - Is msg is valid for this round or a future one
// - Is msg for us and not from us
// - Is the sender a party in the protocol
// - Have we already received a message from the party for this round?
// -
// -
func (s *State) HandleMessage(msg *messages.Message) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.done {
		if err := s.Err(); err != nil {
			return err
		}
		return errors.New("already finished")
	}

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

	s.ackMessage()

	if msg.Type == s.acceptedTypes[0] {
		s.receivedMessages[senderID] = msg
	} else {
		s.queue = append(s.queue, msg)
	}

	return nil
}

func (s *State) ProcessAll() []*messages.Message {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.done {
		return nil
	}

	// Only continue if we received messages from all
	if len(s.receivedMessages) != int(s.params.N()-1) {
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

//
// Output
//
func (s *State) finish() {
	if s.done {
		return
	}
	s.done = true
	s.round.Reset()
	s.stopTimer()
	close(s.doneChan)
}

func (s *State) reportError(err *rounds.Error) {
	if s.done {
		return
	}
	defer s.finish()

	// We already got an error
	// TODO chain the errors
	if s.err == nil {
		err.RoundNumber = s.roundNumber
		s.err = err
	}
}

func (s *State) Done() <-chan struct{} {
	return s.doneChan
}

func (s *State) Err() error {
	if s.err != nil {
		return s.err
	}
	return nil
}

func (s *State) WaitForError() error {
	if !s.done {
		<-s.doneChan
	}
	return s.Err()
}

func (s *State) IsFinished() bool {
	return s.done
}

//
// Timeout
//

type timer struct {
	t *time.Timer
	d time.Duration
}

func newTimer(d time.Duration, f func()) timer {
	var t *time.Timer
	if d > 0 {
		t = time.AfterFunc(d, f)
	}
	return timer{
		t: t,
		d: d,
	}
}

func (t *timer) ackMessage() {
	if t.t != nil {
		t.t.Stop()
		t.t.Reset(t.d)
	}
}

func (t *timer) stopTimer() {
	if t.t != nil {
		t.t.Stop()
	}
}
