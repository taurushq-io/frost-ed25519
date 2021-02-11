package cmd

type Communicator interface {
	Send(to uint32, msg []byte) error
}

type ChannelCommunicator struct {
}
