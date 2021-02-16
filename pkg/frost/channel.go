package frost

import "github.com/taurusgroup/frost-ed25519/pkg/messages"

type Channel struct {
	sendingChannels map[uint32]chan *messages.Message
}

func (c *Channel) Send(msg *messages.Message) error {
	if msg.To == 0 {
		for _, c0 := range c.sendingChannels {
			c0 <- msg
		}
	} else {
		c.sendingChannels[msg.To] <- msg
	}
	return nil
}

func (c *Channel) IncomingChannel(dest uint32) <-chan *messages.Message {
	return c.sendingChannels[dest]
}
