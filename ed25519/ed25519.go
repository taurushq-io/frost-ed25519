//package ed25519

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"io/ioutil"
	"strings"
)

import (
	"crypto/ed25519"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
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

type FKeyGenOutput struct {
	Secrets map[party.ID]*eddsa.SecretShare
	Shares  *eddsa.Public
}

type MPCStateOutput struct {
	State  *state.State
	Output *sign.Output
}

// encode2String takes a slice of byte slices, encodes each to a base64 string,
// and joins them into a single comma-separated string.
func encode2String(data [][]byte) string {
	var base64Strings []string
	for _, bytes := range data {
		encoded := base64.StdEncoding.EncodeToString(bytes)
		base64Strings = append(base64Strings, encoded)
	}
	return strings.Join(base64Strings, ",")
}

// decode2Bytes takes a comma-separated string of base64-encoded data and
// decodes it back into a slice of byte slices.
func decode2Bytes(data string) ([][]byte, error) {
	base64Strings := strings.Split(data, ",")
	var bytesSlices [][]byte
	for _, str := range base64Strings {
		decodedBytes, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err // Handle error if decoding fails
		}
		bytesSlices = append(bytesSlices, decodedBytes)
	}
	return bytesSlices, nil
}

func SliceKeygen(t int, n int) string {

	var err error
	if (n > maxN) || (t >= n) {
		_ = fmt.Errorf("0<t<n<%v", maxN)
		return ""
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
			return ""
		}
	}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n*(n-1)/2)

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
	}

	// Get the public data
	fmt.Println("Group Key:")
	id0 := partyIDs[0]
	if err = states[id0].WaitForError(); err != nil {
		fmt.Println(err)
		return ""
	}
	public := outputs[id0].Public
	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	for _, id := range partyIDs {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println(err)
			return ""
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
			return ""
		}

		slices = append(slices, jsonData)

		gk := kgOutput.Shares.GroupKey.ToEd25519()
		fmt.Printf("groupkey____: %v\n", base64.StdEncoding.EncodeToString(gk))

	}

	fmt.Println("生成分片：-----------------------")
	fmt.Println(slices)

	var encodedKeys = encode2String(slices)
	return encodedKeys
}

func mergeJson(slices [][]byte) ([]byte, error) {
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

func Signature(keys string, msg string) string {

	var err error
	slices, err := decode2Bytes(keys)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	message := []byte(msg)

	if slices == nil {
		fmt.Println("verify failed slices is nil")
		return ""
	}

	mjson, err := mergeJson(slices)

	fmt.Println("msg: ", len(message))
	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput FKeyGenOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	fmt.Println("json: --- ", string(mjson), err)

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return ""
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
			return ""
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
	}

	id0 := partyIDs[0]
	sig := outputs[id0].Signature
	if sig == nil {
		fmt.Println("null signature")
		return ""
	}

	if !ed25519.Verify(pk.ToEd25519(), message, sig.ToEd25519()) {
		fmt.Println("signature verification failed (ed25519)")
		return ""
	}

	if !pk.Verify(message, sig) {
		fmt.Println("signature verification failed")
		return ""
	}

	fmt.Printf("Success: signature is\nr: %x\ns: %x\n", sig.R.Bytes(), sig.S.Bytes())
	sigValue, err := sig.MarshalBinary()
	sigb64 := base64.StdEncoding.EncodeToString(sigValue)
	fmt.Printf("Success: signature is\n%x\n", sigb64)

	pkjson, err := pk.MarshalJSON()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	fmt.Printf("pk: %s\n", string(pkjson))

	return sigb64

}

func VerifySignature(sigvalue string, groupKey string, msg string) bool {

	var pk eddsa.PublicKey
	MESSAGE := []byte(msg)

	pkJson := `"` + groupKey + `"`

	var err error
	err = pk.UnmarshalJSON([]byte(pkJson))
	//err = json.Unmarshal([]byte(groupKey), &pk)
	if err != nil {
		fmt.Printf("pk unmarshal err: %v\n", err)
		return false
	}

	sigData, err := base64.StdEncoding.DecodeString(sigvalue)
	var sig eddsa.Signature
	err = sig.UnmarshalBinary(sigData)
	if err != nil {
		fmt.Printf("sig unmarshal err: %v\n", err)
		return false
	}
	// validate using classic
	if !ed25519.Verify(pk.ToEd25519(), MESSAGE, sig.ToEd25519()) {
		fmt.Printf("验证签名失败")
		return false
	}
	// Validate using our own function
	if !pk.Verify(MESSAGE, &sig) {
		fmt.Printf("验证签名失败")
		return false
	}
	return true
}

// / 还原分片为 kgp
func Key2KGPOutput(partyId string, key string) (FKeyGenOutput, error) {
	// MPC 签名
	slices, err := decode2Bytes(key)
	if err != nil {
		fmt.Println(err)
		return FKeyGenOutput{}, err
	}

	if slices == nil {
		fmt.Println("verify failed slices is nil")
		return FKeyGenOutput{}, fmt.Errorf("verify failed slices is nil")
	}

	mjson, err := mergeJson(slices)

	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput CombinedOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return FKeyGenOutput{}, err
	}

	fmt.Println("json: --- ", string(mjson), err)

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return FKeyGenOutput{}, err
	}

	// get n and t from the keygen output
	var n party.Size
	var t party.Size

	n = party.Size(len(kgOutput.Shares.Shares) + 1)
	t = party.Size(len(kgOutput.Shares.Shares))

	fmt.Printf("(t, n) = (%v, %v)\n", t, n)

	allPartyIDs := helpers.GenerateSet(n)
	var partyIDs []party.ID
	for _, id := range allPartyIDs {
		if id.String() == partyId {
			partyIDs = append(partyIDs, id)
		}
	}
	if len(partyIDs) == 0 {
		return FKeyGenOutput{}, fmt.Errorf("party id %s not found", partyId)
	}
	partyID := partyIDs[0]

	secretStr := kgOutput.Secrets[partyId].Secret
	publicStr := kgOutput.Shares.Shares[partyId]
	secretB, err := base64.StdEncoding.DecodeString(secretStr)
	publicB, err := base64.StdEncoding.DecodeString(publicStr)
	if err != nil {
		fmt.Println(err)
		return FKeyGenOutput{}, err
	}

	var secret ristretto.Scalar
	var public ristretto.Element

	_, err = secret.SetCanonicalBytes(secretB)
	if err != nil {
		fmt.Println(err)
		return FKeyGenOutput{}, err
	}
	_, err = public.SetCanonicalBytes(publicB)
	if err != nil {
		fmt.Println(err)
		return FKeyGenOutput{}, err
	}

	secretShare := eddsa.SecretShare{
		ID:     partyID,
		Secret: secret,
		Public: public,
	}

	secretShares := map[party.ID]*eddsa.SecretShare{
		partyID: &secretShare,
	}

	shares := map[party.ID]*ristretto.Element{
		partyID: &public,
	}

	partySlice := party.IDSlice{
		partyID,
	}

	groupKeyStr := kgOutput.Shares.GroupKey
	var groupKey eddsa.PublicKey
	pkJson := `"` + groupKeyStr + `"`
	err = groupKey.UnmarshalJSON([]byte(pkJson))
	//err = json.Unmarshal([]byte(groupKey), &pk)
	if err != nil {
		fmt.Printf("groupkey unmarshal err: %v\n", err)
		return FKeyGenOutput{}, err
	}

	publicShares := eddsa.Public{
		partySlice,
		party.Size(1),
		shares,
		&groupKey,
	}

	kgp := FKeyGenOutput{
		Secrets: secretShares,
		Shares:  &publicShares,
	}
	return kgp, nil
}

// 分布式签名 第一阶段：产出 output
func MPCInitSign(n int, partyId string, key string, messageStr string) (*MPCStateOutput, error) {

	//// MPC 签名
	//slices, err := decode2Bytes(key)
	//if err != nil {
	//	fmt.Println(err)
	//	return nil, err
	//}
	//

	//
	//if slices == nil {
	//	fmt.Println("verify failed slices is nil")
	//	return nil, fmt.Errorf("verify failed slices is nil")
	//}
	//
	//mjson, err := mergeJson(slices)
	//
	//fmt.Println("msg: ", len(message))
	//fmt.Println("merged: ", string(mjson))
	//fmt.Println("error: ", err)
	//
	//var kgOutput CombinedOutput
	//
	//var jsonData []byte = mjson
	////jsonData, err = ioutil.ReadFile(filename)
	//if err != nil {
	//	fmt.Println(err)
	//	return nil, err
	//}
	//
	//fmt.Println("json: --- ", string(mjson), err)
	//
	//err = json.Unmarshal(jsonData, &kgOutput)
	//if err != nil {
	//	fmt.Println(err)
	//	return nil, err
	//}
	//
	//// get n and t from the keygen output
	//var n party.Size
	//var t party.Size
	//
	//n = party.Size(len(kgOutput.Shares.Shares) + 1)
	//t = party.Size(len(kgOutput.Shares.Shares))
	//
	//fmt.Printf("(t, n) = (%v, %v)\n", t, n)
	//

	allPartyIDs := helpers.GenerateSet(party.Size(n))
	var partyIDs []party.ID
	for _, id := range allPartyIDs {
		if id.String() == partyId {
			partyIDs = append(partyIDs, id)
		}
	}
	if len(partyIDs) == 0 {
		return nil, fmt.Errorf("party id %s not found", partyId)
	}
	partyID := partyIDs[0]
	//
	//secretStr := kgOutput.Secrets[partId].Secret
	//publicStr := kgOutput.Shares.Shares[partId]
	//secretB, err := base64.StdEncoding.DecodeString(secretStr)
	//publicB, err := base64.StdEncoding.DecodeString(publicStr)
	//if err != nil {
	//	fmt.Println(err)
	//	return nil, err
	//}
	//
	//var secret ristretto.Scalar
	//var public ristretto.Element
	//
	//_, err = secret.SetCanonicalBytes(secretB)
	//if err != nil {
	//	fmt.Println(err)
	//	return nil, err
	//}
	//_, err = public.SetCanonicalBytes(publicB)
	//if err != nil {
	//	fmt.Println(err)
	//	return nil, err
	//}
	//
	//secretShare := eddsa.SecretShare{
	//	ID:     partyID,
	//	Secret: secret,
	//	Public: public,
	//}
	//
	//secretShares := map[party.ID]*eddsa.SecretShare{
	//	partyID: &secretShare,
	//}
	//
	//shares := map[party.ID]*ristretto.Element{
	//	partyID: &public,
	//}
	//
	//partySlice := party.IDSlice{
	//	partyID,
	//}
	//
	//groupKeyStr := kgOutput.Shares.GroupKey
	//var groupKey eddsa.PublicKey
	//pkJson := `"` + groupKeyStr + `"`
	//err = groupKey.UnmarshalJSON([]byte(pkJson))
	////err = json.Unmarshal([]byte(groupKey), &pk)
	//if err != nil {
	//	fmt.Printf("groupkey unmarshal err: %v\n", err)
	//	return nil, err
	//}
	//
	//publicShares := eddsa.Public{
	//	partySlice,
	//	party.Size(1),
	//	shares,
	//	&groupKey,
	//}
	//
	////Secrets map[party.ID]*eddsa.SecretShare
	////Shares  *eddsa.Public
	//
	//// structure holding parties' state and output
	//states := map[party.ID]*state.State{}
	//outputs := map[party.ID]*sign.Output{}
	//
	////msgsOut1 := make([][]byte, 0, n)
	////msgsOut2 := make([][]byte, 0, n)

	//var kgp FKeyGenOutput
	kgp, err := Key2KGPOutput(partyId, key)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*sign.Output{}

	secretShares := kgp.Secrets
	publicShares := kgp.Shares

	message := []byte(messageStr)
	states[partyID], outputs[partyID], err = frost.NewSignState(partyIDs, secretShares[partyID], publicShares, message, 0)
	if err != nil {
		fmt.Println()
		return nil, err
	}

	out := MPCStateOutput{
		State:  states[partyID],
		Output: outputs[partyID],
	}
	return &out, nil
}

// 分布式签名 第二阶段： 产出最终签名
//func MPCFinishSign(partId string, stateOut MPCStateOutput, groupKey string, msg string) (string, error) {
//	pk := publicShares.GroupKey
//
//	for _, s := range states {
//		msgs1, err := helpers.PartyRoutine(nil, s)
//		if err != nil {
//			fmt.Println(err)
//			return ""
//		}
//		msgsOut1 = append(msgsOut1, msgs1...)
//	}
//
//	for _, s := range states {
//		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
//		if err != nil {
//			fmt.Println(err)
//			return ""
//		}
//		msgsOut2 = append(msgsOut2, msgs2...)
//	}
//
//	for _, s := range states {
//		_, err := helpers.PartyRoutine(msgsOut2, s)
//		if err != nil {
//			fmt.Println(err)
//			return ""
//		}
//	}
//
//	id0 := partyIDs[0]
//	sig := outputs[id0].Signature
//	if sig == nil {
//		fmt.Println("null signature")
//		return ""
//	}
//
//	if !ed25519.Verify(pk.ToEd25519(), message, sig.ToEd25519()) {
//		fmt.Println("signature verification failed (ed25519)")
//		return ""
//	}
//
//	if !pk.Verify(message, sig) {
//		fmt.Println("signature verification failed")
//		return ""
//	}
//
//	fmt.Printf("Success: signature is\nr: %x\ns: %x\n", sig.R.Bytes(), sig.S.Bytes())
//	sigValue, err := sig.MarshalBinary()
//	sigb64 := base64.StdEncoding.EncodeToString(sigValue)
//	fmt.Printf("Success: signature is\n%x\n", sigb64)
//
//	pkjson, err := pk.MarshalJSON()
//	if err != nil {
//		fmt.Println(err)
//		return ""
//	}
//	fmt.Printf("pk: %s\n", string(pkjson))
//
//	return sigb64
//}

// 分片合成中心化签名
func mpcSignature(keys string, messageStr string) string {

	// MPC 签名
	slices, err := decode2Bytes(keys)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	message := []byte(messageStr)

	if slices == nil {
		fmt.Println("verify failed slices is nil")
		return ""
	}

	mjson, err := mergeJson(slices)

	fmt.Println("msg: ", len(message))
	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput FKeyGenOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	fmt.Println("json: --- ", string(mjson), err)

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return ""
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
			return ""
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
	}

	id0 := partyIDs[0]
	sig := outputs[id0].Signature
	id1 := partyIDs[1]
	sig2 := outputs[id1].Signature
	if sig == nil {
		fmt.Println("null signature")
		return ""
	}

	fmt.Printf("GKED25519: [%v, %v]\n\n", base64.StdEncoding.EncodeToString(pk.ToEd25519()), pk.ToEd25519())

	fmt.Printf("ver111: pk:%v\n message: %v\n sig: %v\n\n", pk.ToEd25519(), message, sig)

	if !ed25519.Verify(pk.ToEd25519(), message, sig.ToEd25519()) {
		fmt.Println("signature verification failed (ed25519)")
		return ""
	}

	if !pk.Verify(message, sig) {
		fmt.Println("signature verification failed")
		return ""
	}

	fmt.Printf("Success: signature is\nr: %x\ns: %x\n", sig.R.Bytes(), sig.S.Bytes())
	fmt.Printf("Success: signatur2 is\nr: %x\ns: %x\n", sig2.R.Bytes(), sig2.S.Bytes())
	sigValue, err := sig.MarshalBinary()

	//return string(sigValue)

	sigb64 := base64.StdEncoding.EncodeToString(sigValue)
	fmt.Printf("Success: signature is\n%x\n", sigb64)

	pkjson, err := pk.MarshalJSON()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	fmt.Printf("pk: %s\n", string(pkjson))

	return string(sig.ToEd25519())
}

func unitTestVerifySignature(filename string) {
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("read file error: %v", err)
		return
	}
	// 定义结构体
	type Data struct {
		Keys      string `json:"keys"`
		GroupKey  string `json:"groupKey"`
		Msg       string `json:"msg"`
		Signature string `json:"signature"`
		Verify    bool   `json:"verify"`
	}
	// 解析 JSON
	var data []Data
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		fmt.Println("json parse Error:", err)
		return
	}

	for i, item := range data {
		//keys := item['keys'];
		groupKey := item.GroupKey
		msg := item.Msg
		signature := item.Signature

		verify := VerifySignature(signature, groupKey, msg)
		fmt.Println(i, verify)
		if verify != true {
			break
		}

	}
}

func main() {
	//keygenDemo(2, 3)

	//keygenDemoV2(2, 3)

	//slices := SliceKeygen(1, 2)
	//sigs := Signature(slices, "message222")
	//fmt.Println("验证结果", sigs)

	//msg := "msg112233*&"
	//keys := SliceKeygen(1, 2)
	//fmt.Printf("keys: %v\n", keys)
	//sig1 := Signature(keys, msg)
	//fmt.Printf("[sig1: %v\n]", sig1)

	//keysList := strings.Split(keys, ",")
	//key1 := strings.Join(keysList, ",")
	//key2 := strings.Join(keysList[:2], ",")
	//sig2 := Signature(keysList[1], msg)
	//sig3 := Signature(key1, msg)
	//sig4 := Signature(key2, msg)
	//fmt.Printf("[sig1: %v\n, sig2: %v\n, sig3: %v\n, sig4: %v\n]", sig1, sig2, sig3, sig4)

	//验签
	//verify1 := VerifySignature("7lRgQEXJEojpyfBmccb0mC8BzNxKYgI0hlgFqQ+xaGf58ch2acpYByT1wqrqP2FlXWmGG+Clv6r5MH3PwnZOBQ==", "3uwHRj188SR7aMQy1LPV0OiigWaZbNp3piwsOWAN7nw=", msg)
	//verify2 := VerifySignature("QqrcpHytkdvxITKoZf3y+TjFUXnPSyYh1nSBOpKhEQBu22mIgyyVKO/sy4yM1HUKW7yq2Noro7al+m5rAzTbBw==", "3uwHRj188SR7aMQy1LPV0OiigWaZbNp3piwsOWAN7nw=", msg)
	//fmt.Printf("验证结果: [%v, %v]", verify1, verify2)

	//verify := VerifySignature(sig, "lFmgvmJr1wQkdnbVZr410gaOHCZbO42xQxVY1DvZnmE=", msg)
	//unitTestVerifySignature("./ed25519_demo.txt")

	//fromAddress := "4xJ3bqT3zsAqBngPoCwtYhJiZ6Ax9riBCdTHKjUUZ5gr"
	//toAddress := "2vvzNTow58DMDZhxyp5SNTxfGXAdHehXY8nyFuRHFy4W"
	//keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAid1lLMHNqQUVmcmNlWU1yaUh1NmNtUnkzQzFrY1ZHMTIrR1pXVGg5STd3WT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAieWxib2haaTV5N3NkblRyanBLYnlxeXNFd3JPRnZ6UUFCTTdJKzRkZlRqMD0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiL0gyVmM4QS9jVS9pREd5OEduenhkcDE2aS90NlVmYzdXUTV3L2VPdHZnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiYk1zWDM3Wks5OWtYdFYyMmZ4MkZ3ZjYzMUlpMkY5eUY5K3FKKzA5MVZBaz0iCiAgfQogfQp9"
	//groupKey := "aM0x+P7wVth5KM9fs6WLjikWYnZQp8mCJYoUzzW/NUo="
	//message := buildSolanaTransactionMsg(fromAddress, toAddress, 333)
	//sig := solanaTransactionTest(keys, message)
	//fmt.Printf("sig: %s\n", sig)
	//verify := VerifySignature(sig, groupKey, message)
	//fmt.Printf("verify: %v\n", verify)

	message := "test010101UUU"

	out, err := MPCInitSign(2, "1", "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAicThZQXdmd1g1QWxrOGx1Vm5wdHk2L2djQzRZYVc1bVpvQTRSdU4ybVZBMD0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiR1AxUzJ3Wmx6NGlpamhhUVBFV2hxMWhUNVF3U1RXeExVWHozN0ZFU1FnYz0iCiAgfQogfQp9", message)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("out: ", out)

}
