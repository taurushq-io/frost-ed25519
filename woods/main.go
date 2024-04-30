package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

const maxN = 100

type Secret struct {
	ID     int    `json:"id"`
	Secret string `json:"secret"`
}

type Shares struct {
	T        int               `json:"t"`
	GroupKey string            `json:"groupkey"`
	Shares   map[string]string `json:"shares"`
}

type CombinedOutput struct {
	Secrets map[string]Secret `json:"Secrets"`
	Shares  Shares            `json:"Shares"`
}

func usage() {
	cmd := filepath.Base(os.Args[0])
	fmt.Printf("usage: %v t n\nwhere 0 < t < n < %v\n", cmd, maxN)
}
func keygenDemo(t int, n int) {

	var err error
	if (n > maxN) || (t >= n) {
		usage()
		return
	}

	partyIDs := helpers.GenerateSet(party.ID(n))

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	// create a state for each party
	for _, id := range partyIDs {
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, party.Size(t), 0)
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
	id0 := partyIDs[0]
	if err = states[id0].WaitForError(); err != nil {
		fmt.Println(err)
		return
	}
	public := outputs[id0].Public
	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	for _, id := range partyIDs {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println(err)
			return
		}
		shareSecret := outputs[id].SecretKey
		sharePublic := public.Shares[id]
		secrets[id] = shareSecret
		fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", id, shareSecret.Secret.Bytes(), sharePublic.Bytes())
	}

	// TODO: write JSON file, to take as input by CLI signer
	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	kgOutput := KeyGenOutput{
		Secrets: secrets,
		Shares:  public,
	}

	var jsonData []byte
	jsonData, err = json.MarshalIndent(kgOutput, "", " ")
	if err != nil {
		fmt.Println(err)
		return
	}

	filename := "./keygenout.json"

	_ = ioutil.WriteFile(filename, jsonData, 0644)

	fmt.Printf("Success: output written to %v\n", filename)
}

func writeJSONToFile(filename string, data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = ioutil.WriteFile(filename, jsonData, 0644)
}

func verifyKeys(filename string, msg string) {

	message := []byte(msg)

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

// 拆分为多份文件
func keygenDemoV2(t int, n int) {

	var err error
	if (n > maxN) || (t >= n) {
		usage()
		return
	}

	partyIDs := helpers.GenerateSet(party.ID(n))

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	// create a state for each party
	for _, id := range partyIDs {
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, party.Size(t), 0)
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
	id0 := partyIDs[0]
	if err = states[id0].WaitForError(); err != nil {
		fmt.Println(err)
		return
	}
	public := outputs[id0].Public
	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	for _, id := range partyIDs {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println(err)
			return
		}
		shareSecret := outputs[id].SecretKey
		sharePublic := public.Shares[id]
		secrets[id] = shareSecret
		fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", id, shareSecret.Secret.Bytes(), sharePublic.Bytes())
	}

	// TODO: write JSON file, to take as input by CLI signer
	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	var slices [][]byte
	for _, id := range partyIDs {

		// 创建一个新的 map 用于存储过滤后的 secretShare
		filteredSecrets := make(map[party.ID]*eddsa.SecretShare)

		// 遍历原始的 secrets map
		for nid, secret := range secrets {
			// 如果ID不等于'2'，则将其添加到新的 map 中
			if nid == id {
				filteredSecrets[id] = secret
			}
		}

		filteredShares := make(map[party.ID]*ristretto.Element)
		filteredShares[id] = public.Shares[id]

		filteredPubs := &eddsa.Public{
			partyIDs,
			party.Size(t),
			filteredShares,
			public.GroupKey,
		}

		kgOutput := KeyGenOutput{
			Secrets: filteredSecrets,
			Shares:  filteredPubs,
		}
		var jsonData []byte
		jsonData, err = json.MarshalIndent(kgOutput, "", " ")
		if err != nil {
			fmt.Println(err)
			return
		}

		filename := fmt.Sprintf("./keygenout_%d.json", id)

		_ = ioutil.WriteFile(filename, jsonData, 0644)

		fmt.Printf("Success: output written to %v %v\n", filename, jsonData)

		slices = append(slices, jsonData)

	}

	fmt.Println("生成分片：-----------------------")
	fmt.Println(slices)

	//kgOutput := KeyGenOutput{
	//	Secrets: secrets,
	//	Shares:  public,
	//}
	//
	//var jsonData []byte
	//jsonData, err = json.MarshalIndent(kgOutput, "", " ")
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//
	//filename := "./keygenout.json"
	//
	//_ = ioutil.WriteFile(filename, jsonData, 0644)
	//
	//fmt.Printf("Success: output written to %v\n", filename)
}

// 读取 json 文件合并
func mergeJson(filename string, n int) ([]byte, error) {
	combinedOutput := CombinedOutput{
		Secrets: make(map[string]Secret),
		Shares:  Shares{Shares: make(map[string]string)},
	}

	for i := 1; i <= n; i++ {
		filei := fmt.Sprintf("%v_%d.json", filename, i)
		data, err := ioutil.ReadFile(filei)
		if err != nil {
			return nil, err
		}

		var output CombinedOutput
		err = json.Unmarshal(data, &output)
		if err != nil {
			return nil, err
		}

		// Merge the secrets from each file
		for key, secret := range output.Secrets {
			combinedOutput.Secrets[key] = secret
		}

		// Merge the shares from each file
		for key, value := range output.Shares.Shares {
			combinedOutput.Shares.Shares[key] = value
		}

		// Update other fields if needed
		if combinedOutput.Shares.T == 0 {
			combinedOutput.Shares.T = output.Shares.T
			combinedOutput.Shares.GroupKey = output.Shares.GroupKey
		}
	}

	combinedJSON, err := json.MarshalIndent(combinedOutput, "", "  ")
	if err != nil {
		return nil, err
	}

	return combinedJSON, nil
}

func verifyKeysV2(filename string, msg string, rn int) {

	message := []byte(msg)

	var err error

	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	mjson, err := mergeJson(filename, rn)

	fmt.Println("msg: ", len(message))
	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput KeyGenOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("json: --- ", string(mjson), err)

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

func keygenDemoV3(t int, n int) [][]byte {

	var err error
	if (n > maxN) || (t >= n) {
		usage()
		return nil
	}

	partyIDs := helpers.GenerateSet(party.ID(n))

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	// create a state for each party
	for _, id := range partyIDs {
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, party.Size(t), 0)
		if err != nil {
			fmt.Println(err)
			return nil
		}
	}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n*(n-1)/2)

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return nil
		}
	}

	// Get the public data
	fmt.Println("Group Key:")
	id0 := partyIDs[0]
	if err = states[id0].WaitForError(); err != nil {
		fmt.Println(err)
		return nil
	}
	public := outputs[id0].Public
	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	for _, id := range partyIDs {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println(err)
			return nil
		}
		shareSecret := outputs[id].SecretKey
		sharePublic := public.Shares[id]
		secrets[id] = shareSecret
		fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", id, shareSecret.Secret.Bytes(), sharePublic.Bytes())
	}

	// TODO: write JSON file, to take as input by CLI signer
	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	var slices [][]byte
	for _, id := range partyIDs {

		// 创建一个新的 map 用于存储过滤后的 secretShare
		filteredSecrets := make(map[party.ID]*eddsa.SecretShare)

		// 遍历原始的 secrets map
		for nid, secret := range secrets {
			// 如果ID不等于'2'，则将其添加到新的 map 中
			if nid == id {
				filteredSecrets[id] = secret
			}
		}

		filteredShares := make(map[party.ID]*ristretto.Element)
		filteredShares[id] = public.Shares[id]

		filteredPubs := &eddsa.Public{
			partyIDs,
			party.Size(t),
			filteredShares,
			public.GroupKey,
		}

		kgOutput := KeyGenOutput{
			Secrets: filteredSecrets,
			Shares:  filteredPubs,
		}
		var jsonData []byte
		jsonData, err = json.MarshalIndent(kgOutput, "", " ")
		if err != nil {
			fmt.Println(err)
			return nil
		}

		slices = append(slices, jsonData)

	}

	fmt.Println("生成分片：-----------------------")
	fmt.Println(slices)
	return slices

}

func mergeJsonV3(slices [][]byte) ([]byte, error) {
	combinedOutput := CombinedOutput{
		Secrets: make(map[string]Secret),
		Shares:  Shares{Shares: make(map[string]string)},
	}

	var err error
	for i := 0; i < len(slices); i++ {
		data := slices[i]

		var output CombinedOutput
		err = json.Unmarshal(data, &output)
		if err != nil {
			return nil, err
		}

		// Merge the secrets from each file
		for key, secret := range output.Secrets {
			combinedOutput.Secrets[key] = secret
		}

		// Merge the shares from each file
		for key, value := range output.Shares.Shares {
			combinedOutput.Shares.Shares[key] = value
		}

		// Update other fields if needed
		if combinedOutput.Shares.T == 0 {
			combinedOutput.Shares.T = output.Shares.T
			combinedOutput.Shares.GroupKey = output.Shares.GroupKey
		}
	}

	combinedJSON, err := json.MarshalIndent(combinedOutput, "", "  ")
	if err != nil {
		return nil, err
	}

	return combinedJSON, nil
}

func verifyKeysV3(slices [][]byte, msg string) {

	message := []byte(msg)

	var err error

	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	mjson, err := mergeJsonV3(slices)

	fmt.Println("msg: ", len(message))
	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput KeyGenOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("json: --- ", string(mjson), err)

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

func VerifyKeysV4(n int) {

	N := party.Size(n)
	T := N - 1

	//入参
	sharesJson := `
	{
			"t": 2,
			"groupkey": "fK+pxejfoZOClWjBhooCFyxgM4lNzhM53a0fAzTzuhg=",
			"shares": {
			"1": "2sZH71/TLsoCvSi7zgGiPTl163IDTtx9ZQFa7SIgmlM=",
			"2": "GIWwGwhNoSxrW1H06q2IvMaW9huPpkctlAdrdqPaizE=",
			"3": "2OxhRtZ1SGM3QxYfxc/PYU2pGIXdhtXmZScOuGU+CiE="
		}
	}
	`

	secretJson1 := `{
		"id": 1,
		"secret": "6OFN//k0riGrEgXpZXPHo+Wqhq2Bv3874crktgbvqQE="
	}
	`

	secretJson2 := `{
		"id": 2,
		"secret": "q7bnenQx5eNK2Pn/EpfJzqvDK9ENbV8WZo2PwdJm0QY="
	}
	`

	secretJson3 := `{
		"id": 3,
		"secret": "aDeElB1TghLHKeCCI3uv1OG31g4Hqz4qmVxk7l/ljgs="
	}
	`

	MESSAGE := []byte("test111222")
	var err error
	var publicShares eddsa.Public
	var secret1 eddsa.SecretShare
	var secret2 eddsa.SecretShare
	var secret3 eddsa.SecretShare
	secretShares := make(map[party.ID]*eddsa.SecretShare)
	partyIDs := helpers.GenerateSet(N)

	err = json.Unmarshal([]byte(sharesJson), &publicShares)
	if err != nil {
		fmt.Printf("json fail: %x", err)
		return
	}

	err = json.Unmarshal([]byte(secretJson1), &secret1)
	err = json.Unmarshal([]byte(secretJson2), &secret2)
	err = json.Unmarshal([]byte(secretJson3), &secret3)
	if err != nil {
		fmt.Printf("json fail: %x", err)
		return
	}
	secretShares[party.ID(1)] = &secret1
	secretShares[party.ID(2)] = &secret2
	secretShares[party.ID(3)] = &secret3

	fmt.Printf("-------T: %d\n %x\n", T, partyIDs)

	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*sign.Output{}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	for _, id := range partyIDs {
		var err error
		states[id], outputs[id], err = frost.NewSignState(partyIDs, secretShares[id], &publicShares, MESSAGE, 0)
		if err != nil {
			fmt.Printf("generate state err: %v\n", err)
		}
	}

	//生成签名

	var start time.Time
	start = time.Now()
	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Printf("routine1 fail: %v", err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}
	fmt.Println("finish round 0", time.Since(start))

	start = time.Now()
	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Printf("routine2 fail: %v", err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}
	fmt.Println("finish round 1", time.Since(start))

	start = time.Now()
	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Printf("routine3 fail: %v", err)
		}
	}
	fmt.Println("finish round 2", time.Since(start))

	sig := outputs[1].Signature
	sig2 := outputs[1].Signature
	sig3 := outputs[1].Signature
	if sig == nil {
		fmt.Printf("生成签名为空")
		return
	}
	fmt.Printf("生成签名: [R:%x,S:%x]\n", sig.R.Bytes(), sig.S.Bytes())
	fmt.Printf("生成签名: [R:%x,S:%x]\n", sig2.R.Bytes(), sig2.S.Bytes())
	fmt.Printf("生成签名: [R:%x,S:%x]\n", sig3.R.Bytes(), sig3.S.Bytes())

	//验证签名
	pk := publicShares.GroupKey
	// validate using classic
	if !ed25519.Verify(pk.ToEd25519(), MESSAGE, sig.ToEd25519()) {
		fmt.Printf("验证签名失败")
		return
	}
	// Validate using our own function
	if !pk.Verify(MESSAGE, sig) {
		fmt.Printf("验证签名失败")
		return
	}
	// Check all publicKeys return the same sig
	for id, s := range states {
		if err := s.WaitForError(); err != nil {
			fmt.Printf("wait state fail")
			return
		}

		comparedSig := outputs[id].Signature
		sigBytes, err := sig.MarshalBinary()
		if err != nil {
			fmt.Printf("sigbytes fail")
			return
		}

		comparedSigBytes, err := comparedSig.MarshalBinary()
		if err != nil {
			fmt.Printf("sigbytes fail")
			return
		}
		if !bytes.Equal(sigBytes, comparedSigBytes) {
			fmt.Printf("签名不一致")
			return
		}
	}
	fmt.Printf("验证签名成功")
}

func main() {
	//keygenDemo(2, 3)

	//verifyKeys("/Users/wuxi/code/mine/frost-ed25519/woods/keygenout3.json", "message_test111")
	//verifyKeysV2("/Users/wuxi/code/mine/frost-ed25519/woods/keygenout3.json", "message_test111", 3)
	//keygenDemoV2(2, 3)

	//verifyKeysV2("/Users/wuxi/code/mine/frost-ed25519/keygenout", "message222", 3)

	//slices := keygenDemoV3(2, 3)
	//verifyKeysV3(slices, "message222")
	VerifyKeysV4(3)
}
