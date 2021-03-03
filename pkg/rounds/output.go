package rounds

import (
	"sync"
)

type Output interface {
	WaitForError() error
}

type BaseOutput struct {
	doneChan chan *Error
	err      error
	mtx      sync.Mutex
}

func NewBaseOutput() *BaseOutput {
	return &BaseOutput{
		// We use a buffered channel of capacity 1 so that
		// we never block if no one is listening
		doneChan: make(chan *Error, 1),
	}
}

func (o *BaseOutput) Abort(err error) {
	o.mtx.Lock()
	defer o.mtx.Unlock()

	// We already got an error
	// TODO chain the errors
	if o.err != nil {
		return
	}

	o.err = err

	// don't do anything, we already got an error
	if o.doneChan == nil {
		return
	}
	close(o.doneChan)
	o.doneChan = nil
}

func (o *BaseOutput) IsFinished() bool {
	o.mtx.Lock()
	defer o.mtx.Unlock()

	return o.doneChan == nil
}

func (o *BaseOutput) WaitForError() error {
	if o.err != nil {
		return o.err
	}
	if o.doneChan == nil {
		return nil
	}
	select {
	case err := <-o.doneChan:
		o.err = err
		return err
	}
}
