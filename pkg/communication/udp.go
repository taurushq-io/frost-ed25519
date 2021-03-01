package communication

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"

	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

type UDP struct {
	peers    map[uint32]*net.UDPAddr
	incoming chan *messages.Message
	conn     *net.UDPConn
	id       uint32
}

func NewUDPCommunicator(ID uint32) (c *UDP, id uint32, ip string) {
	if ID == 0 {
		ID = rand.Uint32()
	}
	id = ID

	l, err := net.ListenUDP("udp4", nil)
	if err != nil {
		panic(err)
	}
	ip = l.LocalAddr().String()

	c = &UDP{
		peers:    map[uint32]*net.UDPAddr{},
		incoming: make(chan *messages.Message, 10),
		conn:     l,
		id:       id,
	}
	return
}

func (c *UDP) AddPeer(id uint32, ip string) {
	addr, _ := net.ResolveUDPAddr("udp4", ip)
	c.peers[id] = addr
}

func (c *UDP) Start() {
	go func() {
		defer c.conn.Close()
		initialBuffer := make([]byte, 77+(len(c.peers)+1)*64)
		// max buffer =
		// 9 header
		// 64 proof
		// 4 len
		// 64 * n
		// 77 + n*64

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
	if msg.To == 0 {
		for _, ip := range c.peers {
			_, err = c.conn.WriteToUDP(b, ip)
			if err != nil {
				return err
			}
		}
	} else if msg.To != c.id {
		_, err = c.conn.WriteToUDP(b, c.peers[msg.To])
		return err
	}
	return nil
}

func (c *UDP) Incoming() <-chan *messages.Message {
	return c.incoming
}

func (c *UDP) Done() {
	close(c.incoming)
	c.conn.Close()
}
