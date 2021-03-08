package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

const maxN = 100

func usage() {
	cmd := filepath.Base(os.Args[0])
	fmt.Printf("usage: %v t n\nwhere 0 < t < n < %v\n", cmd, maxN)
}

func main() {

	if len(os.Args) != 3 {
		usage()
		return
	}

	var err error
	var t int
	var n int

	t, err = strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
		usage()
		return
	}
	n, err = strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println(err)
		usage()
		return
	}
	if (n > maxN) || (t >= n) {
		usage()
		return
	}

	partySet := helpers.GenerateSet(party.ID(n))

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	// create a state for each party
	for id := range partySet.Range() {
		states[id], outputs[id], err = frost.NewKeygenState(id, partySet, party.Size(t), 0)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n*(n-1)/2)

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println(err)
			return
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Get the public data
	fmt.Println("Group Key:")
	id0 := partySet.Sorted()[0]
	if err = states[id0].WaitForError(); err != nil {
		fmt.Println(err)
		return
	}
	public := outputs[id0].Public
	groupKey := public.GroupKey()
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	for _, id := range partySet.Sorted() {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println(err)
			return
		}
		shareSecret := outputs[id].SecretKey
		sharePublic, _ := public.Share(id)
		fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", id, shareSecret.Scalar().Bytes(), sharePublic.ToEd25519())
	}

	// TODO: write JSON file, to take as input by CLI signer

	fmt.Println("OK")
}
