package communication

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type UDP struct {
	peers    map[party.ID]*net.UDPAddr
	incoming chan *messages.Message
	conn     *net.UDPConn
	id       party.ID
}

func NewUDPCommunicator(id party.ID, laddr *net.UDPAddr) (c *UDP, ip string) {
	l, err := net.ListenUDP("udp4", nil)
	if err != nil {
		panic(err)
	}
	ip = l.LocalAddr().String()

	c = &UDP{
		peers:    map[party.ID]*net.UDPAddr{},
		incoming: make(chan *messages.Message, 10),
		conn:     l,
		id:       id,
	}
	return
}

func (c *UDP) AddPeer(id party.ID, ip string) {
	addr, _ := net.ResolveUDPAddr("udp4", ip)
	c.peers[id] = addr
}

func (c *UDP) Start() {
	go func() {
		defer func() {
			if c.conn != nil {
				c.conn.Close()
			}
		}()

		initialBuffer := make([]byte, (len(c.peers)+2)*64)

		for {
			n, _, err := c.conn.ReadFromUDP(initialBuffer)
			if err != nil && !errors.Is(err, io.EOF) {
				if strings.HasSuffix(err.Error(), "use of closed network connection") {
					return
				}
				fmt.Println("read error:", err)
				return
			}
			var msg messages.Message
			err = msg.UnmarshalBinary(initialBuffer[:n])
			if err != nil {
				fmt.Println("read error:", err)
			}
			c.incoming <- &msg
		}
	}()
}

func (c *UDP) Send(msg *messages.Message) error {

	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if msg.IsBroadcast() {
		for _, ip := range c.peers {
			_, err = c.conn.WriteToUDP(b, ip)
			if err != nil {
				return err
			}
		}
	} else if to := msg.To; to != c.id {
		_, err = c.conn.WriteToUDP(b, c.peers[to])
		return err
	}
	return nil
}

func (c *UDP) Incoming() <-chan *messages.Message {
	if c.conn == nil {
		return nil
	}
	return c.incoming
}

func (c *UDP) Done() {
	if c.conn == nil {
		return
	}
	close(c.incoming)
	c.conn.Close()
}

func (c *UDP) Timeout() time.Duration {
	return 1500 * time.Millisecond
}
