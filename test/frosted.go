package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/communication"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
)

func Setup(N, T party.Size) (message []byte, keygenIDs, signIDs []party.ID) {
	message = []byte("hello")
	keygenIDs = make([]party.ID, 0, N)
	for id := party.Size(0); id < N; id++ {
		keygenIDs = append(keygenIDs, 42+id)
	}
	signIDs = make([]party.ID, T+1)
	copy(signIDs, keygenIDs)
	return
}

func DoKeygen(N, T party.Size, keygenIDs []party.ID, keygenComm map[party.ID]communication.Communicator) (*eddsa.Shares, map[party.ID]*eddsa.PrivateKey, error) {
	var err error
	keygenHandlers := make(map[party.ID]*KeyGenHandler, N)
	for _, id := range keygenIDs {
		keygenHandlers[id], err = NewKeyGenHandler(keygenComm[id], id, keygenIDs, T)
		if err != nil {
			return nil, nil, err
		}
	}

	var shares *eddsa.Shares
	secrets := map[party.ID]*eddsa.PrivateKey{}
	for id, h := range keygenHandlers {
		var secret *eddsa.PrivateKey
		if _, shares, secret, err = h.WaitForKeygenOutput(); err != nil {
			return nil, nil, err
		}
		secrets[id] = secret
	}
	return shares, secrets, nil
}

func DoSign(T party.Size, signIDs []party.ID, shares *eddsa.Shares, secrets map[party.ID]*eddsa.PrivateKey, signComm map[party.ID]communication.Communicator, message []byte) error {
	groupKey := shares.GroupKey()
	signHandlers := make(map[party.ID]*SignHandler, T+1)
	var err error
	for _, id := range signIDs {
		signHandlers[id], err = NewSignHandler(signComm[id], id, signIDs, secrets[id], shares, message)
		if err != nil {
			return err
		}
	}

	failures := 0

	for _, h := range signHandlers {
		s, err := h.WaitForSignOutput()

		if err != nil {
			failures++
		} else if s != nil {
			if !s.Verify(message, groupKey) || !ed25519.Verify(groupKey.ToEdDSA(), message, s.ToEdDSA()) {
				failures++
			}
		}
	}

	if failures != 0 {
		return fmt.Errorf("%v signatures verifications failed", failures)
	}
	return nil
}

func FROSTestUDP(N, T party.Size) error {
	fmt.Printf("Using UDP:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	keygenComm := communication.NewUDPCommunicatorMap(keygenIDs)
	defer destroyCommMap(keygenComm)
	shares, secrets, err := DoKeygen(N, T, keygenIDs, keygenComm)
	if err != nil {
		return err
	}

	signComm := communication.NewUDPCommunicatorMap(signIDs)
	defer destroyCommMap(signComm)

	return DoSign(T, signIDs, shares, secrets, signComm, message)
}

func FROSTestChannel(N, T party.Size) error {
	fmt.Printf("Using Channels:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	keygenComm := communication.NewChannelCommunicatorMap(keygenIDs)
	defer destroyCommMap(keygenComm)
	shares, secrets, err := DoKeygen(N, T, keygenIDs, keygenComm)
	if err != nil {
		return err
	}

	signComm := communication.NewChannelCommunicatorMap(signIDs)
	defer destroyCommMap(signComm)

	return DoSign(T, signIDs, shares, secrets, signComm, message)
}

func destroyCommMap(m map[party.ID]communication.Communicator) {
	for _, c := range m {
		c.Done()
	}
}

func FROSTestMonkey(N, T party.Size) error {
	fmt.Printf("Using Monkey Channels:\n(n, t) = (%v, %v): ", N, T)

	message, keygenIDs, signIDs := Setup(N, T)
	keygenComm := communication.NewMonkeyChannelCommunicatorMap(keygenIDs, messages.MessageTypeKeyGen1)
	keygenCommNormal := communication.NewChannelCommunicatorMap(keygenIDs)

	defer destroyCommMap(keygenComm)
	defer destroyCommMap(keygenCommNormal)

	_, _, err := DoKeygen(N, T, keygenIDs, keygenComm)
	if err == nil {
		return errors.New("failed to fail")
	} else {
		fmt.Println("good fail: ", err)
	}
	shares, secrets, err := DoKeygen(N, T, keygenIDs, keygenCommNormal)
	if err != nil {
		return err
	}

	signComm1 := communication.NewMonkeyChannelCommunicatorMap(signIDs, messages.MessageTypeSign1)
	defer destroyCommMap(signComm1)

	if err = DoSign(T, signIDs, shares, secrets, signComm1, message); err == nil {
		return errors.New("failed to fail")
	} else {
		fmt.Println("good fail: ", err)
	}
	signComm2 := communication.NewMonkeyChannelCommunicatorMap(signIDs, messages.MessageTypeSign2)
	defer destroyCommMap(signComm2)
	if err = DoSign(T, signIDs, shares, secrets, signComm2, message); err == nil {
		return errors.New("failed to fail")
	} else {
		fmt.Println("good fail: ", err)
	}
	return nil
}

func main() {
	ns := []party.Size{5, 10, 50}

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
