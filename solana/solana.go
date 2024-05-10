// package solana
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/types"
	"github.com/davecgh/go-spew/spew"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
	"github.com/gagliardetto/solana-go/rpc/ws"
	//"github.com/blocto/solana-go-sdk/types"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	//"github.com/blocto/solana-go-sdk/rpc"
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

	tx.Message.SetVersion(solana.MessageVersionV0)

	// 指定头部信息
	//tx.Message.Header = solana.MessageHeader{
	//	NumRequiredSignatures:       1, // 设置需要的签名数量
	//	NumReadonlySignedAccounts:   0, // 设置只读已签名账户数量
	//	NumReadonlyUnsignedAccounts: 0, // 设置只读未签名账户数量
	//}

	//tx.Message.SetVersion(solana.MessageVersionV0)

	messageBytes, err := tx.Message.MarshalBinary()
	messageJson, err := tx.Message.MarshalJSON()
	messageb64 := base64.StdEncoding.EncodeToString(messageBytes)

	message642, err := tx.ToBase64()

	if err != nil {
		log.Fatalf("serialize message error, err: %v", err)
	}

	fmt.Printf("Serialized Message for Signature: %x\n, %v\n", messageBytes, string(messageJson)) //msg := "交易信息"

	fmt.Printf("messageb64: [%v\n, %v\n]", messageb64, message642)

	//return string(messageBytes)

	mbb, _ := tx.Message.MarshalLegacy()
	return string(mbb)

	//return message642
}

func solanaTransactionSignature(keys string, messageStr string, toEd25519 bool) string {

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

	if toEd25519 {
		//return base64.StdEncoding.EncodeToString(sig.ToEd25519())

		sig1 := sig.ToEd25519()
		sig2 := []byte(string(sig.ToEd25519()))
		sig3 := base64.StdEncoding.EncodeToString(sig.ToEd25519())
		sig4, _ := base64.StdEncoding.DecodeString(sig3)
		fmt.Println(sig1, sig2, sig3, sig4)

		fmt.Printf("sig333: [%v, %v]\n\n", string(sig.ToEd25519()), []byte(string(sig.ToEd25519())))
		return string(sig.ToEd25519())
	}
	return sigb64

}

func solanaSendTransaction(signature string, msgHash string) {
	// 创建交易
	rpcClient := rpc.New(rpc.DevNet_RPC)

	msg, err := types.MessageDeserialize([]byte(msgHash))

	if err != nil {
		fmt.Printf("partse msg fail: %v\n", err)
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

	transaction, err := types.TransactionDeserialize(rawTx)
	if err != nil {
		log.Fatalf("Failed to deserialize transaction: %v", err)
	}
	fmt.Println("transaction: ", transaction)

	// 输出序列化后的交易长度和内容，查看是否正常
	fmt.Printf("Serialized transaction length: %d, content: %x\n", len(rawTx), rawTx)
	txb64 := base64.StdEncoding.EncodeToString(rawTx)
	fmt.Printf("Transaction length: %d, b64content: %x\n", len(txb64), txb64)

	// 发送交易
	//txHash, err := rpcClient.SendEncodedTransaction(context.Background(), txb64)
	txHash, err := rpcClient.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction has been sent with hash: %s\n", txHash)
}

func buildSolanaTransactionMsgV1(from string, to string, amount uint64, keys string, toEd25519 bool) {
	// Create a new RPC client:
	rpcClient := rpc.New(rpc.DevNet_RPC)

	fromB, err := base64.StdEncoding.DecodeString(from)
	toB, err := base64.StdEncoding.DecodeString(to)
	accountFrom := solana.PublicKeyFromBytes(fromB)
	accountTo := solana.PublicKeyFromBytes(toB)

	fmt.Printf("fromPubKey: %v", fromB)

	if err != nil {
		panic(err)
		return
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

	//tx.Message.SetVersion(solana.MessageVersionV0)

	// 指定头部信息
	//tx.Message.Header = solana.MessageHeader{
	//	NumRequiredSignatures:       1, // 设置需要的签名数量
	//	NumReadonlySignedAccounts:   0, // 设置只读已签名账户数量
	//	NumReadonlyUnsignedAccounts: 0, // 设置只读未签名账户数量
	//}

	//tx.Message.SetVersion(solana.MessageVersionV0)

	messageBytes, err := tx.Message.MarshalBinary()
	messageJson, err := tx.Message.MarshalJSON()
	messageb64 := base64.StdEncoding.EncodeToString(messageBytes)

	message642, err := tx.ToBase64()

	if err != nil {
		log.Fatalf("serialize message error, err: %v", err)
	}

	fmt.Printf("Serialized Message for Signature: %x\n, %v\n", messageBytes, string(messageJson)) //msg := "交易信息"

	fmt.Printf("messageb64: [%v\n, %v\n]", messageb64, message642)

	//return string(messageBytes)

	//mbb, _ := tx.Message.MarshalLegacy()

	sig := solanaTransactionSignature(keys, string(messageBytes), toEd25519)

	fmt.Printf("sig444: [%v, %v]\n\n", sig, []byte(sig))

	//bb1, _ := base64.StdEncoding.DecodeString(messageb64)
	//bb2, _ := base64.StdEncoding.DecodeString(message642)
	//sig := solanaTransactionSignature(keys, string(bb2), toEd25519)
	//sig := solanaTransactionSignature(keys, message642, toEd25519)

	// 将签名解码为字节片
	signature := solana.SignatureFromBytes([]byte(sig))
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}
	fmt.Printf("Signature: %x\n", signature)

	tx.Signatures = append(tx.Signatures, signature)

	isSigner1 := tx.IsSigner(accountFrom)
	isSigner2 := tx.IsSigner(accountTo)
	fmt.Printf("isSigner: [%v, %v]\n", isSigner1, isSigner2)

	//使用ed25519 签名校验
	fmt.Printf("ver222: pk:%v\n message: %v\n sig: %v\n\n", fromB, messageBytes, []byte(sig))
	fmt.Printf("sig555: [%v, %v]\n\n", sig, []byte(sig))
	edver := ed25519.Verify(fromB, messageBytes, []byte(sig))
	if !edver {
		panic("ed25519 signature verification failed")
	}

	//签名校验
	err = tx.VerifySignatures() // 将签名追加到交易的签名字段中
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
		return
	}

	//txb64, err := tx.ToBase64()

	if err != nil {
		fmt.Printf("Failed to serialize transaction: %v", err)
		return
	}

	wsClient, err := ws.Connect(context.Background(), rpc.DevNet_WS)
	if err != nil {
		panic(err)
	}
	fsig, err := confirm.SendAndConfirmTransaction(
		context.Background(),
		rpcClient,
		wsClient,
		tx,
	)
	if err != nil {
		fmt.Printf("Failed to send confirmation: %v", err)
	}
	spew.Dump(sig)

	fmt.Println(fsig)

}

func solanaFaucet(pubkey string, amount uint64) {
	c := client.NewClient(rpc.DevNet_RPC)

	accountB, _ := base64.StdEncoding.DecodeString(pubkey)
	account := solana.PublicKeyFromBytes(accountB)

	// request for 1 SOL airdrop using RequestAirdrop()
	txhash, err := c.RequestAirdrop(
		context.TODO(),   // request context
		account.String(), // wallet address requesting airdrop
		amount,           // amount of SOL in lamport
	)
	// check for errors
	if err != nil {
		panic(err)
	}
	fmt.Printf("txhash: %s\n", txhash)

}

func solanaGetBalance(pubkey string) {

	c := client.NewClient(rpc.DevNet_RPC)

	accountB, _ := base64.StdEncoding.DecodeString(pubkey)
	account := solana.PublicKeyFromBytes(accountB)
	// get balance
	balance, err := c.GetBalance(
		context.TODO(),
		account.String(),
	)
	if err != nil {
		fmt.Printf("failed to get balance, err: %v", err)
	}
	fmt.Printf("balance: %v\n", balance)

	// get balance with sepcific commitment
	balance, err = c.GetBalanceWithConfig(
		context.TODO(),
		account.String(),
		client.GetBalanceConfig{
			Commitment: rpc.CommitmentProcessed,
		},
	)
	if err != nil {
		fmt.Printf("failed to get balance with cfg, err: %v", err)
	}
	fmt.Printf("balance: %v\n", balance)

	// for advanced usage. fetch full rpc response
	res, err := c.RpcClient.GetBalance(
		context.TODO(),
		account.String(),
	)
	if err != nil {
		fmt.Printf("failed to get balance via rpc client, err: %v", err)
	}
	fmt.Printf("response: %+v\n", res)
}

func solTransTestv2() {

	keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAicThZQXdmd1g1QWxrOGx1Vm5wdHk2L2djQzRZYVc1bVpvQTRSdU4ybVZBMD0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiR1AxUzJ3Wmx6NGlpamhhUVBFV2hxMWhUNVF3U1RXeExVWHozN0ZFU1FnYz0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAicEc0Vk00cTg2SVFFQ1FJS09uMG5mQzBIQXhIL0lCV1hkeGsrZXBNUHJnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiWEdiYlF5Nlh1SjNvdU1XL2tjZmFZT3lRYUNyWVNPYUdNaHRhNDBjSlZ5bz0iCiAgfQogfQp9"
	//
	//from1 := "GzIZ/Uxza5+dMwqIiUBK5JbfBfKoHZxYXSfgXgKgVfo="
	//to1 := "g890V/MLnTTTsKXF2Abd8xvSLzaXtrO4H4RvzhxK7iU="
	//buildSolanaTransactionMsgV1(from1, to1, 333, keys, false)
	//
	////groupkey
	//from2 := "xK3aTO1KBWarLY5QlxEPUxGlgyyQY7oPR4aQJM8C/Co="
	//to2 := "QtXA0VMuarDYLFz7JlrcUqfVKRgxI2iXzicN9jqqixA="
	//buildSolanaTransactionMsgV1(from2, to2, 333, keys, true)

	from3 := "GzIZ/Uxza5+dMwqIiUBK5JbfBfKoHZxYXSfgXgKgVfo="
	to3 := "g890V/MLnTTTsKXF2Abd8xvSLzaXtrO4H4RvzhxK7iU="

	fmt.Printf("%v,%v,%v", keys, from3, to3)
	solanaFaucet(from3, 2^9)
	//buildSolanaTransactionMsgV1(from3, to3, 333000, keys, true)
	//
	//from4 := "xK3aTO1KBWarLY5QlxEPUxGlgyyQY7oPR4aQJM8C/Co="
	//to4 := "QtXA0VMuarDYLFz7JlrcUqfVKRgxI2iXzicN9jqqixA="
	//buildSolanaTransactionMsgV1(from4, to4, 333, keys, false)

	//from5 := "GP1S2wZlz4iijhaQPEWhq1hT5QwSTWxLUXz37FESQgc="
	//to5 := "XgqVOXSBimes357Xn6XIwljwy4hVXkCx2oEG4qcbvA0="
	//buildSolanaTransactionMsgV1(from5, to5, 333, keys, false)

}

func main() {

	//fromAddress := "4xJ3bqT3zsAqBngPoCwtYhJiZ6Ax9riBCdTHKjUUZ5gr"
	//toAddress := "2vvzNTow58DMDZhxyp5SNTxfGXAdHehXY8nyFuRHFy4W"

	//fromAddress := "5PRaxeTyOWPgoPskPkRQnG6yLtLAsHRVUkAv905VJGg="
	//toAddress := "6S/NS3JLCmCm3TRbqf5HYHnv7ZsFZC47B+FKrQ1YZRw="
	//
	//keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAiUDA1N0hkUDU1bnVoNW1KdkE5dGVYUXBCQWo4dldVS1VCVVdFSFJBYUdRdz0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJJS1pVWUYwbURpN2crbnRzV0dvV2ZhWWlCNFhZSml1MVhEZ0RMcG5CekNRPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiWE1vOVY1M1I4cWxKc3ppOG9OcWh4TlB4MGRLOU1VNHp3WEtFeExnV3hraz0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiRzF4cjBTQ1NXU0xjUVJzaUpUUjlLMGxuc0J3bUdEaDB3WWxlMGNqRStRND0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJJS1pVWUYwbURpN2crbnRzV0dvV2ZhWWlCNFhZSml1MVhEZ0RMcG5CekNRPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiMk5KT1R2ek5ZOVZFQXJOQXVtV2s2Z1VtZFVZL2NuZTNlTFM2VGY3YTRFdz0iCiAgfQogfQp9"

	//fromAddress := "aM0x+P7wVth5KM9fs6WLjikWYnZQp8mCJYoUzzW/NUo="
	//toAddress := "nBUq+N5LyHilcuYfeOhVHDDYZekNMsMatTvoHuKelUg="
	//
	//keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAid1lLMHNqQUVmcmNlWU1yaUh1NmNtUnkzQzFrY1ZHMTIrR1pXVGg5STd3WT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAieWxib2haaTV5N3NkblRyanBLYnlxeXNFd3JPRnZ6UUFCTTdJKzRkZlRqMD0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiL0gyVmM4QS9jVS9pREd5OEduenhkcDE2aS90NlVmYzdXUTV3L2VPdHZnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiYk1zWDM3Wks5OWtYdFYyMmZ4MkZ3ZjYzMUlpMkY5eUY5K3FKKzA5MVZBaz0iCiAgfQogfQp9"

	//groupKey := "aM0x+P7wVth5KM9fs6WLjikWYnZQp8mCJYoUzzW/NUo="
	//message := buildSolanaTransactionMsg(fromAddress, toAddress, 333)
	//sig := solanaTransactionSignature(keys, message)
	//fmt.Printf("sig: %v\n", sig)
	//verify := VerifySignature(sig, groupKey, message)
	//fmt.Printf("verify: %v\n", verify)
	//solanaSendTransaction(sig, message)

	//buildSolanaTransactionMsgV2(fromAddress, toAddress, 333, keys)

	solTransTestv2()
}
