package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
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

	for id := range partySet.Range() {
		var err error
		states[id], outputs[id], err = frost.NewKeygenState(id, partySet, party.Size(t), 0)

	}
}
