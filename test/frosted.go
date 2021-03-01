package main

import (
	"errors"
	"fmt"
	"time"

	frost "github.com/taurusgroup/frost-ed25519/pkg"
	"github.com/taurusgroup/frost-ed25519/pkg/communication"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

func Setup(N, T uint32) (message []byte, keygenIDs, signIDs []uint32) {
	message = []byte("hello")
	keygenIDs = make([]uint32, 0, N)
	for id := uint32(0); id < N; id++ {
		keygenIDs = append(keygenIDs, 42+id)
	}
	signIDs = make([]uint32, T+1)
	copy(signIDs, keygenIDs)
	return
}

func DoKeygen(N uint32, T uint32, keygenIDs []uint32, keygenComm map[uint32]communication.Communicator) (*eddsa.Shares, map[uint32]*eddsa.PrivateKey, error) {
	var err error
	keygenHandlers := make(map[uint32]*frost.KeyGenHandler, N)
	for _, id := range keygenIDs {
		keygenHandlers[id], err = frost.NewKeyGenHandler(keygenComm[id], id, keygenIDs, T)
		if err != nil {
			return nil, nil, err
		}
	}

	var shares *eddsa.Shares
	secrets := map[uint32]*eddsa.PrivateKey{}
	for id, h := range keygenHandlers {
		var secret *eddsa.PrivateKey
		if _, shares, secret, err = h.WaitForKeygenOutput(); err != nil {
			return nil, nil, err
		}
		secrets[id] = secret
	}
	return shares, secrets, nil
}

func DoSign(T uint32, signIDs []uint32, shares *eddsa.Shares, secrets map[uint32]*eddsa.PrivateKey, signComm map[uint32]communication.Communicator, message []byte) error {
	groupKey, err := shares.GroupKey(nil)
	if err != nil {
		return err
	}
	signHandlers := make(map[uint32]*frost.SignHandler, T+1)
	for _, id := range signIDs {
		signHandlers[id], _ = frost.NewSignHandler(signComm[id], id, signIDs, secrets[id], shares, message)
	}

	failures := 0

	for _, h := range signHandlers {
		s, err := h.WaitForSignOutput()

		if err != nil {
			failures++
		} else if s != nil && !s.Verify(message, groupKey) {
			failures++
		}
	}

	if failures != 0 {
		return fmt.Errorf("%v signatures verifications failed", failures)
	}
	return nil
}

func FROSTestUDP(N, T uint32) error {
	fmt.Printf("Using UDP:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	keygenComm := communication.NewUDPCommunicatorMap(keygenIDs)

	shares, secrets, err := DoKeygen(N, T, keygenIDs, keygenComm)
	if err != nil {
		return err
	}

	signComm := communication.NewUDPCommunicatorMap(signIDs)

	return DoSign(T, signIDs, shares, secrets, signComm, message)
}

func FROSTestChannel(N, T uint32) error {
	fmt.Printf("Using Channels:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	keygenComm := communication.NewChannelCommunicatorMap(keygenIDs)

	shares, secrets, err := DoKeygen(N, T, keygenIDs, keygenComm)
	if err != nil {
		return err
	}

	signComm := communication.NewChannelCommunicatorMap(signIDs)

	return DoSign(T, signIDs, shares, secrets, signComm, message)
}

func FROSTestMonkey(N, T uint32) error {
	fmt.Printf("Using Monkey Channels:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	keygenComm := communication.NewMonkeyChannelCommunicatorMap(keygenIDs, messages.MessageTypeKeyGen1)
	keygenCommNormal := communication.NewChannelCommunicatorMap(keygenIDs)

	_, _, err := DoKeygen(N, T, keygenIDs, keygenComm)
	if err == nil {
		return errors.New("failed to fail")
	}
	shares, secrets, err := DoKeygen(N, T, keygenIDs, keygenCommNormal)
	if err != nil {
		return err
	}

	signComm1 := communication.NewMonkeyChannelCommunicatorMap(signIDs, messages.MessageTypeSign1)

	if err = DoSign(T, signIDs, shares, secrets, signComm1, message); err == nil {
		return errors.New("failed to fail")
	}
	signComm2 := communication.NewMonkeyChannelCommunicatorMap(signIDs, messages.MessageTypeSign2)
	if err = DoSign(T, signIDs, shares, secrets, signComm2, message); err == nil {
		return errors.New("failed to fail")
	}
	return nil
}

func main() {
	ns := []uint32{5, 10, 50}

	// what should work
	for _, n := range ns {
		start := time.Now()
		err := FROSTestUDP(n, n/2)
		elapsed := time.Since(start)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestUDP(n, n-1)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		elapsed = time.Since(start)
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestChannel(n, n/2)
		elapsed = time.Since(start)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestChannel(n, n-1)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		elapsed = time.Since(start)
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestMonkey(n, n/2)
		elapsed = time.Since(start)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("ok")
		}
		fmt.Printf("%s\n", elapsed)

		start = time.Now()
		err = FROSTestMonkey(n, n-1)
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
		if FROSTestUDP(n, n) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
		if FROSTestUDP(n, 0) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
		if FROSTestUDP(n, n*10) == nil {
			fmt.Println("ERROR: failed to fail")
		} else {
			fmt.Println("ok (failed)")
		}
	}
}
