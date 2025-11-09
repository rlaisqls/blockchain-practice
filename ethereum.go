package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	privateKeyHex := os.Getenv("PRIVATE_KEY_HEX")
	privateKey, _ := crypto.HexToECDSA(privateKeyHex)
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	fmt.Println("================================================================================")
	fmt.Println("Account Information")
	fmt.Println("================================================================================")
	fmt.Printf("From Address: %s\n", fromAddress.Hex())
	fmt.Printf("Private Key: %s\n", privateKeyHex)
	fmt.Printf("Public Key: %x\n", crypto.FromECDSAPub(publicKeyECDSA))

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		fmt.Printf("Failed to connect to client: %v\n", err)
		return
	}

	fmt.Println("\n================================================================================")
	fmt.Println("Network Information")
	fmt.Println("================================================================================")

	// Chain ID
	chainID, _ := client.ChainID(context.Background())
	fmt.Printf("Chain ID: %s\n", chainID.String())

	// Latest block number
	blockNumber, _ := client.BlockNumber(context.Background())
	fmt.Printf("Latest Block Number: %d\n", blockNumber)

	// Network ID
	networkID, _ := client.NetworkID(context.Background())
	fmt.Printf("Network ID: %s\n", networkID.String())

	fmt.Println("\n================================================================================")
	fmt.Println("From Address Balance & Details")
	fmt.Println("================================================================================")

	// From address 잔고
	fromBalance, _ := client.BalanceAt(context.Background(), fromAddress, nil)
	fromBalanceEth := new(big.Float).Quo(new(big.Float).SetInt(fromBalance), big.NewFloat(1e18))
	fmt.Printf("Balance: %s wei (%s ETH)\n", fromBalance.String(), fromBalanceEth.String())

	// Nonce 가져오기
	nonce, _ := client.PendingNonceAt(context.Background(), fromAddress)
	fmt.Printf("Nonce (Transaction Count): %d\n", nonce)

	// Code 확인 (컨트랙트 여부)
	fromCode, _ := client.CodeAt(context.Background(), fromAddress, nil)
	fmt.Printf("Is Contract: %v\n", len(fromCode) > 0)
	if len(fromCode) > 0 {
		fmt.Printf("Contract Code Length: %d bytes\n", len(fromCode))
	}

	// Gas price 가져오기
	gasPrice, _ := client.SuggestGasPrice(context.Background())
	gasPriceGwei := new(big.Float).Quo(new(big.Float).SetInt(gasPrice), big.NewFloat(1e9))
	fmt.Printf("\nSuggested Gas Price: %s wei (%s Gwei)\n", gasPrice.String(), gasPriceGwei.String())

	// 트랜잭션 생성
	toAddress := common.HexToAddress("0xb8c35efdbca898b8dcde1ffd4ccab66e44c7dd41")

	fmt.Println("\n================================================================================")
	fmt.Println("To Address Balance & Details")
	fmt.Println("================================================================================")
	fmt.Printf("To Address: %s\n", toAddress.Hex())

	// To address 잔고 (전송 전)
	toBalanceBefore, _ := client.BalanceAt(context.Background(), toAddress, nil)
	toBalanceBeforeEth := new(big.Float).Quo(new(big.Float).SetInt(toBalanceBefore), big.NewFloat(1e18))
	fmt.Printf("Balance (Before): %s wei (%s ETH)\n", toBalanceBefore.String(), toBalanceBeforeEth.String())

	// To address code 확인
	toCode, _ := client.CodeAt(context.Background(), toAddress, nil)
	fmt.Printf("Is Contract: %v\n", len(toCode) > 0)
	if len(toCode) > 0 {
		fmt.Printf("Contract Code Length: %d bytes\n", len(toCode))
	}

	value := big.NewInt(10000) // 1 ETH in wei
	valueEth := new(big.Float).Quo(new(big.Float).SetInt(value), big.NewFloat(1e18))
	gasLimit := uint64(21000) // 기본 전송

	fmt.Println("\n================================================================================")
	fmt.Println("Transaction Details")
	fmt.Println("================================================================================")
	fmt.Printf("From: %s\n", fromAddress.Hex())
	fmt.Printf("To: %s\n", toAddress.Hex())
	fmt.Printf("Value: %s wei (%s ETH)\n", value.String(), valueEth.String())
	fmt.Printf("Gas Limit: %d\n", gasLimit)
	fmt.Printf("Gas Price: %s wei (%s Gwei)\n", gasPrice.String(), gasPriceGwei.String())

	maxTxCost := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit)))
	maxTxCostEth := new(big.Float).Quo(new(big.Float).SetInt(maxTxCost), big.NewFloat(1e18))
	fmt.Printf("Max Transaction Fee: %s wei (%s ETH)\n", maxTxCost.String(), maxTxCostEth.String())

	totalCost := new(big.Int).Add(value, maxTxCost)
	totalCostEth := new(big.Float).Quo(new(big.Float).SetInt(totalCost), big.NewFloat(1e18))
	fmt.Printf("Total Cost (Value + Max Fee): %s wei (%s ETH)\n", totalCost.String(), totalCostEth.String())
	fmt.Printf("Nonce: %d\n", nonce)
	fmt.Printf("Chain ID: %s\n", chainID.String())

	tx := types.NewTransaction(
		nonce,
		toAddress,
		value,
		gasLimit,
		gasPrice,
		nil, // data
	)

	fmt.Println("\n================================================================================")
	fmt.Println("Transaction Signing")
	fmt.Println("================================================================================")
	fmt.Printf("Transaction Hash (unsigned): %s\n", tx.Hash().Hex())
	fmt.Printf("Transaction Size: %d bytes\n", tx.Size())

	// 서명
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		fmt.Printf("Failed to sign transaction: %v\n", err)
		return
	}

	fmt.Printf("Transaction Hash (signed): %s\n", signedTx.Hash().Hex())

	// V, R, S 값 출력
	v, r, s := signedTx.RawSignatureValues()
	fmt.Printf("Signature V: %s\n", v.String())
	fmt.Printf("Signature R: %s\n", r.String())
	fmt.Printf("Signature S: %s\n", s.String())

	// 브로드캐스트
	fmt.Println("\n================================================================================")
	fmt.Println("📡 Broadcasting Transaction")
	fmt.Println("================================================================================")

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Printf("❌ Transaction broadcast failed: %v\n", err)
		fmt.Printf("   Transaction Hash (attempted): %s\n", signedTx.Hash().Hex())
		fmt.Printf("\n💡 Common reasons:\n")
		fmt.Printf("   - Insufficient balance (need %s wei + gas)\n", value.String())
		fmt.Printf("   - Nonce too low/high\n")
		fmt.Printf("   - Gas price too low\n")
		fmt.Printf("   - Account doesn't exist or has no funds\n")
		return
	}

	fmt.Printf("Transaction sent successfully!\n")
	fmt.Printf("Transaction Hash: %s\n", signedTx.Hash().Hex())

	// 트랜잭션 해시 검증
	if signedTx.Hash().Hex() == "0x0000000000000000000000000000000000000000000000000000000000000000" {
		fmt.Printf("⚠️  Warning: Invalid transaction hash detected!\n")
		return
	}

	fmt.Println("\n================================================================================")
	fmt.Println("Waiting for transaction receipt...")
	fmt.Println("================================================================================")

	// Receipt 대기 (선택적)
	receipt, err := waitForReceipt(client, signedTx.Hash(), 30)
	if err != nil {
		fmt.Printf("⚠️  Could not get receipt: %v\n", err)
		fmt.Println("(Transaction may still be pending)")
	} else {
		fmt.Printf("Transaction confirmed!\n")
		fmt.Printf("Block Number: %d\n", receipt.BlockNumber.Uint64())
		fmt.Printf("Block Hash: %s\n", receipt.BlockHash.Hex())
		fmt.Printf("Gas Used: %d (%.2f%%)\n", receipt.GasUsed, float64(receipt.GasUsed)/float64(gasLimit)*100)
		fmt.Printf("Cumulative Gas Used: %d\n", receipt.CumulativeGasUsed)
		fmt.Printf("Status: %d ", receipt.Status)
		if receipt.Status == 1 {
			fmt.Println("(Success)")
		} else {
			fmt.Println("(Failed)")
		}
		fmt.Printf("Logs Count: %d\n", len(receipt.Logs))

		// 실제 트랜잭션 수수료 계산
		actualFee := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		actualFeeEth := new(big.Float).Quo(new(big.Float).SetInt(actualFee), big.NewFloat(1e18))
		fmt.Printf("Actual Transaction Fee: %s wei (%s ETH)\n", actualFee.String(), actualFeeEth.String())

		// 최종 잔고 확인
		fmt.Println("\n================================================================================")
		fmt.Println("Final Balances")
		fmt.Println("================================================================================")

		fromBalanceAfter, _ := client.BalanceAt(context.Background(), fromAddress, nil)
		fromBalanceAfterEth := new(big.Float).Quo(new(big.Float).SetInt(fromBalanceAfter), big.NewFloat(1e18))
		fmt.Printf("From Address Balance: %s wei (%s ETH)\n", fromBalanceAfter.String(), fromBalanceAfterEth.String())

		fromBalanceDiff := new(big.Int).Sub(fromBalance, fromBalanceAfter)
		fromBalanceDiffEth := new(big.Float).Quo(new(big.Float).SetInt(fromBalanceDiff), big.NewFloat(1e18))
		fmt.Printf("  Change: -%s wei (-%s ETH)\n", fromBalanceDiff.String(), fromBalanceDiffEth.String())

		toBalanceAfter, _ := client.BalanceAt(context.Background(), toAddress, nil)
		toBalanceAfterEth := new(big.Float).Quo(new(big.Float).SetInt(toBalanceAfter), big.NewFloat(1e18))
		fmt.Printf("\nTo Address Balance: %s wei (%s ETH)\n", toBalanceAfter.String(), toBalanceAfterEth.String())

		toBalanceDiff := new(big.Int).Sub(toBalanceAfter, toBalanceBefore)
		toBalanceDiffEth := new(big.Float).Quo(new(big.Float).SetInt(toBalanceDiff), big.NewFloat(1e18))
		fmt.Printf("  Change: +%s wei (+%s ETH)\n", toBalanceDiff.String(), toBalanceDiffEth.String())
	}

	fmt.Println("\n================================================================================")
	fmt.Println("Done!")
	fmt.Println("================================================================================")
}

// waitForReceipt waits for a transaction receipt with timeout
func waitForReceipt(client *ethclient.Client, txHash common.Hash, timeoutSeconds int) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for receipt")
		case <-ticker.C:
			receipt, err := client.TransactionReceipt(context.Background(), txHash)
			if err == nil {
				return receipt, nil
			}
			fmt.Print(".")
		}
	}
}
