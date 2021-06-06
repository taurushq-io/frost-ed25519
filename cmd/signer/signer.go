package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func usage() {
	cmd := filepath.Base(os.Args[0])
	fmt.Printf("usage: %v <JSON file> message\n", cmd)
}

func main() {

	if len(os.Args) != 3 {
		usage()
		return
	}

	filename := os.Args[1]
	message := []byte(os.Args[2])

	var err error

	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	var kgOutput KeyGenOutput

	var jsonData []byte
	jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return
	}

	// get n and t from the keygen output
	var n party.Size
	var t party.Size

	n = kgOutput.Shares.PartyIDs.N()
	t = kgOutput.Shares.Threshold

	fmt.Printf("(t, n) = (%v, %v)\n", t, n)

	partyIDs := helpers.GenerateSet(n)
	secretShares := kgOutput.Secrets
	publicShares := kgOutput.Shares

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*sign.Output{}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n)

	for _, id := range partyIDs {
		states[id], outputs[id], err = frost.NewSignState(partyIDs, secretShares[id], publicShares, message, 0)
		if err != nil {
			fmt.Println()
		}
	}

	pk := publicShares.GroupKey

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

	id0 := partyIDs[0]
	sig := outputs[id0].Signature
	if sig == nil {
		fmt.Println("null signature")
		return
	}

	if !ed25519.Verify(pk.ToEd25519(), message, sig.ToEd25519()) {
		fmt.Println("signature verification failed (ed25519)")
		return
	}

	if !pk.Verify(message, sig) {
		fmt.Println("signature verification failed")
		return
	}

	fmt.Printf("Success: signature is\nr: %x\ns: %x\n", sig.R.Bytes(), sig.S.Bytes())
}
