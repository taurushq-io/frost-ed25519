package communication

import (
	"log"
	"sync"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type Channel struct {
	channels map[uint32]chan []byte
	incoming chan *messages.Message
	receiver uint32
	wg       *sync.WaitGroup
	done     chan struct{}
}

func (c *Channel) Send(msg *messages.Message) error {
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if msg.To == 0 {
		for id, ch := range c.channels {
			if id != c.receiver {
				ch <- b
			}
		}
	} else if msg.To != c.receiver {
		c.channels[msg.To] <- b
	}
	return nil
}

func (c *Channel) Incoming() <-chan *messages.Message {
	return c.incoming
}

func (c *Channel) Done() {
	c.wg.Done()
	close(c.incoming)
}

func waitForFinish(wg *sync.WaitGroup, done chan struct{}, chans map[uint32]chan []byte) {
	wg.Wait()
	close(done)
	for _, c := range chans {
		close(c)
	}
}

func (c *Channel) handleByteChan() {
	for {
		select {
		case <-c.done:
			return
		case data := <-c.channels[c.receiver]:
			if data == nil {
				continue
			}
			var msg messages.Message
			err := msg.UnmarshalBinary(data)
			if err != nil {
				log.Print(err)
				continue
			}
			c.incoming <- &msg
		}
	}
}

func NewChannelCommunicatorForAll(partyIDs []uint32) map[uint32]*Channel {
	var wg sync.WaitGroup

	n := len(partyIDs)
	wg.Add(n)
	done := make(chan struct{})

	byteChannels := make(map[uint32]chan []byte, n)
	for _, id := range partyIDs {
		byteChannels[id] = make(chan []byte, n)
	}
	go waitForFinish(&wg, done, byteChannels)

	cs := make(map[uint32]*Channel, n)
	for _, id := range partyIDs {
		incoming := make(chan *messages.Message, n)
		c := &Channel{
			channels: byteChannels,
			incoming: incoming,
			receiver: id,
			wg:       &wg,
			done:     done,
		}
		go c.handleByteChan()
		cs[id] = c
	}
	return cs
}
