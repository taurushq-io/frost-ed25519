package main

import (
	"fmt"
	"time"

	frost "github.com/taurusgroup/frost-ed25519/pkg"
	"github.com/taurusgroup/frost-ed25519/pkg/communication"
)

func setupUDP(IDs []uint32) map[uint32]*communication.UDP {
	comms := map[uint32]*communication.UDP{}
	addresses := map[uint32]string{}
	for _, id := range IDs {
		comms[id], _, addresses[id] = communication.NewUDPCommunicator(id)
	}
	for id1, c := range comms {
		for id2, addr := range addresses {
			if id1 != id2 {
				c.AddPeer(id2, addr)
			}
		}
		c.Start()
	}
	return comms
}

func FROSTest(N, T uint32) error {
	fmt.Printf("(n, t) = (%v, %v): ", N, T)

	message := []byte("hello")

	keygenIDs := make([]uint32, 0, N)
	for id := uint32(0); id < N; id++ {
		keygenIDs = append(keygenIDs, 2*id+10)
	}

	signIDs := make([]uint32, T+1)
	copy(signIDs, keygenIDs)

	var err error

	//keygenComm := setupUDP(keygenIDs)
	keygenComm := communication.NewChannelCommunicatorForAll(keygenIDs)
	keygenHandlers := make(map[uint32]*frost.KeyGenHandler, N)
	for _, id := range keygenIDs {
		keygenHandlers[id], err = frost.NewKeyGenHandler(keygenComm[id], id, keygenIDs, T)
		if err != nil {
			return err
		}
	}

	party1 := keygenIDs[0]
	// obtain the public key from the first party and wait for the others
	groupKey, _, _, err := keygenHandlers[party1].WaitForKeygenOutput()
	if err != nil {
		return err
	}

	for _, h := range keygenHandlers {
		if _, _, _, err := h.WaitForKeygenOutput(); err != nil {
			return err
		}
	}

	signComm := setupUDP(signIDs)
	//signComm := communication.NewChannelCommunicatorForAll(signIDs)
	signHandlers := make(map[uint32]*frost.SignHandler, T+1)
	for _, id := range signIDs {
		_, publicShares, secretShare, err := keygenHandlers[id].WaitForKeygenOutput()
		if err != nil {
			return err
		}
		signHandlers[id], _ = frost.NewSignHandler(signComm[id], id, signIDs, secretShare, publicShares, message)
	}

	failures := 0

	for _, h := range signHandlers {
		s, _ := h.WaitForSignOutput()
		if !s.Verify(message, groupKey) {
			failures++
		}
	}

	if failures != 0 {
		return fmt.Errorf("%v signatures verifications failed\n", failures)
	}
	return nil
}

func main() {
	ns := []uint32{5, 10, 50}

	// what should work
	for _, n := range ns {
		start := time.Now()
		err := FROSTest(n, n/2)
		elapsed := time.Since(start)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTest(n, n-1)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		elapsed = time.Since(start)
		fmt.Printf("%s\n", elapsed)
	}

	// what should NOT work, but should not panic
	for _, n := range ns {
		if FROSTest(n, n) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
		if FROSTest(n, 0) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
		if FROSTest(n, n*10) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
	}
}
