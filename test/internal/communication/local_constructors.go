package communication

import (
	"sync"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

func NewUDPCommunicatorMap(IDs []party.ID) map[party.ID]Communicator {
	comms := map[party.ID]Communicator{}
	addresses := map[party.ID]string{}
	for _, id := range IDs {
		comms[id], addresses[id] = NewUDPCommunicator(id, nil)
	}
	for id1, c := range comms {
		for id2, addr := range addresses {
			if id1 != id2 {
				c.(*UDP).AddPeer(id2, addr)
			}
		}
		c.(*UDP).Start()
	}
	return comms
}

func NewChannelCommunicatorMap(partyIDs []party.ID) map[party.ID]Communicator {
	var wg sync.WaitGroup

	n := len(partyIDs)
	wg.Add(n)
	done := make(chan struct{})

	byteChannels := make(map[party.ID]chan []byte, n)
	for _, id := range partyIDs {
		byteChannels[id] = make(chan []byte, n)
	}
	go waitForFinish(&wg, done, byteChannels)

	cs := make(map[party.ID]Communicator, n)
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
