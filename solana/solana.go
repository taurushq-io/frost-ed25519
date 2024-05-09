// package solana
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/blocto/solana-go-sdk/types"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
	"log"
	"strings"
)

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

func buildSolanaTransactionMsg(from string, to string, amount uint64) string {
	// Create a new RPC client:
	rpcClient := rpc.New(rpc.DevNet_RPC)

	accountFrom, err := solana.PublicKeyFromBase58(from)
	accountTo, err := solana.PublicKeyFromBase58(to)
	if err != nil {
		panic(err)
		return ""
	}

	recent, err := rpcClient.GetRecentBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		panic(err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(
				amount,
				accountFrom,
				accountTo,
			).Build(),
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(accountFrom),
	)
	if err != nil {
		panic(err)
	}

	messageBytes, err := tx.Message.MarshalBinary()
	messageJson, err := tx.Message.MarshalJSON()

	if err != nil {
		log.Fatalf("serialize message error, err: %v", err)
	}

	fmt.Printf("Serialized Message for Signature: %x\n, %v\n", messageBytes, string(messageJson)) //msg := "交易信息"

	return string(messageBytes)

}

func solanaTransactionSignature(keys string, messageStr string) string {

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

	//return string(sigValue)

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

func solanaSendTransaction(signature string, msgHash string) {
	// 创建交易
	rpcClient := rpc.New(rpc.DevNet_RPC)

	msg, err := types.MessageDeserialize([]byte(msgHash))
	if err != nil {
		panic(err)
		return
	}

	tx := types.Transaction{
		Signatures: []types.Signature{
			[]byte(signature),
		},
		Message: msg,
	}

	//// 将交易编码
	rawTx, err := tx.Serialize()

	if err != nil {
		log.Fatalf("Failed to serialize transaction: %v", err)
	}

	// 输出序列化后的交易长度和内容，查看是否正常
	fmt.Printf("Serialized transaction length: %d, content: %x\n", len(rawTx), rawTx)
	//txb64 := base64.StdEncoding.EncodeToString(rawTx)
	//fmt.Printf("Transaction length: %d, content: %x\n", len(txb64), txb64)

	// 发送交易
	txHash, err := rpcClient.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction has been sent with hash: %s\n", txHash)
}

func main() {

	fromAddress := "4xJ3bqT3zsAqBngPoCwtYhJiZ6Ax9riBCdTHKjUUZ5gr"
	toAddress := "2vvzNTow58DMDZhxyp5SNTxfGXAdHehXY8nyFuRHFy4W"
	keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAid1lLMHNqQUVmcmNlWU1yaUh1NmNtUnkzQzFrY1ZHMTIrR1pXVGg5STd3WT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAieWxib2haaTV5N3NkblRyanBLYnlxeXNFd3JPRnZ6UUFCTTdJKzRkZlRqMD0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiL0gyVmM4QS9jVS9pREd5OEduenhkcDE2aS90NlVmYzdXUTV3L2VPdHZnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiYk1zWDM3Wks5OWtYdFYyMmZ4MkZ3ZjYzMUlpMkY5eUY5K3FKKzA5MVZBaz0iCiAgfQogfQp9"
	//groupKey := "aM0x+P7wVth5KM9fs6WLjikWYnZQp8mCJYoUzzW/NUo="
	message := buildSolanaTransactionMsg(fromAddress, toAddress, 333)
	sig := solanaTransactionSignature(keys, message)
	fmt.Printf("sig: %v\n", sig)
	//verify := VerifySignature(sig, groupKey, message)
	//fmt.Printf("verify: %v\n", verify)
	solanaSendTransaction(sig, message)
}
