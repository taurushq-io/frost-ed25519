package state

//
//type Ba2seOutput struct {
//	doneChan chan *rounds.Error
//	err      *rounds.Error
//	mtx      sync.Mutex
//}
//
//func NewBaseOutput() *BaseOutput {
//	return &BaseOutput{
//		// We use a buffered channel of capacity 1 so that
//		// we never block if no one is listening
//		doneChan: make(chan *rounds.Error, 1),
//	}
//}
//
//func (o *BaseOutput) ReportError(err *rounds.Error) {
//	o.mtx.Lock()
//	defer o.mtx.Unlock()
//
//	// We already got an error
//	// TODO chain the errors
//	if o.err != nil {
//		return
//	}
//
//	o.err = err
//
//	// don't do anything, we already got an error
//	if o.doneChan == nil {
//		return
//	}
//	close(o.doneChan)
//	o.doneChan = nil
//}
//
//func (o *BaseOutput) IsFinished() bool {
//	o.mtx.Lock()
//	defer o.mtx.Unlock()
//
//	return o.doneChan == nil
//}
//
//func (o *BaseOutput) WaitForError() *rounds.Error {
//	if o.err != nil {
//		return o.err
//	}
//	if o.doneChan == nil {
//		return nil
//	}
//	err := <-o.doneChan
//	o.err = err
//	return o.err
//}
