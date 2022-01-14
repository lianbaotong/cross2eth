package ethtxs

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/33cn/plugincgo/plugin/crypto/secp256k1hsm/adapter"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/lianbaotong/cross2eth/ebrelayer/relayer/ethereum/ethinterface"
)

//EthTxStatus ...
type EthTxStatus int32

type NonceMutex struct {
	Nonce  int64
	RWLock *sync.RWMutex
}

var addr2Nonce = make(map[common.Address]NonceMutex)

//String ...
func (ethTxStatus EthTxStatus) String() string {
	return [...]string{"Fail", "Success", "Pending"}[ethTxStatus]
}

//const
const (
	PendingDuration4TxExeuction = 300
	EthTxPending                = EthTxStatus(2)
)

func getNonce4MultiEth(sender common.Address, client ethinterface.EthClientSpec, addr2TxNonce map[common.Address]*NonceMutex) (*big.Int, error) {
	if nonceMutex, exist := addr2TxNonce[sender]; exist {
		nonceMutex.RWLock.Lock()
		defer nonceMutex.RWLock.Unlock()
		nonceMutex.Nonce++
		addr2TxNonce[sender] = nonceMutex
		txslog.Debug("getNonce from cache", "address", sender.String(), "nonce", nonceMutex.Nonce)
		return big.NewInt(nonceMutex.Nonce), nil
	}

	nonce, err := client.PendingNonceAt(context.Background(), sender)
	if nil != err {
		return nil, err
	}
	txslog.Debug("getNonce", "address", sender.String(), "nonce", nonce)
	n := new(NonceMutex)
	n.Nonce = int64(nonce)
	n.RWLock = new(sync.RWMutex)
	addr2TxNonce[sender] = n
	return big.NewInt(int64(nonce)), nil
}

func revokeNonce4MultiEth(sender common.Address, addr2TxNonce map[common.Address]*NonceMutex) (*big.Int, error) {
	if nonceMutex, exist := addr2TxNonce[sender]; exist {
		nonceMutex.RWLock.Lock()
		defer nonceMutex.RWLock.Unlock()
		nonceMutex.Nonce--
		addr2TxNonce[sender] = nonceMutex
		txslog.Debug("revokeNonce", "address", sender.String(), "nonce", nonceMutex.Nonce)
		return big.NewInt(nonceMutex.Nonce), nil
	}
	return nil, errors.New("address doesn't exist tx")
}

func getNonce(sender common.Address, client ethinterface.EthClientSpec) (*big.Int, error) {
	if nonceMutex, exist := addr2Nonce[sender]; exist {
		nonceMutex.RWLock.Lock()
		defer nonceMutex.RWLock.Unlock()
		nonceMutex.Nonce++
		addr2Nonce[sender] = nonceMutex
		txslog.Debug("getNonce from cache", "address", sender.String(), "nonce", nonceMutex.Nonce)
		return big.NewInt(nonceMutex.Nonce), nil
	}

	nonce, err := client.PendingNonceAt(context.Background(), sender)
	if nil != err {
		return nil, err
	}
	txslog.Debug("getNonce", "address", sender.String(), "nonce", nonce)
	n := new(NonceMutex)
	n.Nonce = int64(nonce)
	n.RWLock = new(sync.RWMutex)
	addr2Nonce[sender] = *n
	return big.NewInt(int64(nonce)), nil
}

func revokeNonce(sender common.Address) (*big.Int, error) {
	if nonceMutex, exist := addr2Nonce[sender]; exist {
		nonceMutex.RWLock.Lock()
		defer nonceMutex.RWLock.Unlock()
		nonceMutex.Nonce--
		addr2Nonce[sender] = nonceMutex
		txslog.Debug("revokeNonce", "address", sender.String(), "nonce", nonceMutex.Nonce)
		return big.NewInt(nonceMutex.Nonce), nil
	}
	return nil, errors.New("address doesn't exist tx")
}

//PrepareAuth ...
func PrepareAuth(client ethinterface.EthClientSpec, privateKey *ecdsa.PrivateKey, transactor common.Address) (*bind.TransactOpts, error) {
	if nil == privateKey || nil == client {
		txslog.Error("PrepareAuth", "nil input parameter", "client", client, "privateKey", privateKey)
		return nil, errors.New("nil input parameter")
	}

	ctx := context.Background()
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		txslog.Error("PrepareAuth", "Failed to SuggestGasPrice due to:", err.Error())
		return nil, errors.New("failed to get suggest gas price " + err.Error())
	}

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		txslog.Error("PrepareAuth NetworkID", "err", err)
		return nil, err
	}

	_, isSim := client.(*ethinterface.SimExtend)
	if isSim {
		chainID = big.NewInt(1337)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		txslog.Error("PrepareAuth NewKeyedTransactorWithChainID", "err", err, "chainID", chainID)
		return nil, err
	}
	auth.Value = big.NewInt(0) // in wei
	auth.GasLimit = GasLimit4Deploy
	auth.GasPrice = gasPrice

	if auth.Nonce, err = getNonce(transactor, client); err != nil {
		return nil, err
	}

	return auth, nil
}

func PrepareAuth4MultiEthereum(client ethinterface.EthClientSpec, privateKey *ecdsa.PrivateKey, transactor common.Address, addr2TxNonce map[common.Address]*NonceMutex) (*bind.TransactOpts, error) {
	if nil == privateKey || nil == client {
		txslog.Error("PrepareAuth", "nil input parameter", "client", client, "privateKey", privateKey)
		return nil, errors.New("nil input parameter")
	}

	ctx := context.Background()
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		txslog.Error("PrepareAuth", "Failed to SuggestGasPrice due to:", err.Error())
		return nil, errors.New("failed to get suggest gas price " + err.Error())
	}

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		txslog.Error("PrepareAuth NetworkID", "err", err)
		return nil, err
	}

	_, isSim := client.(*ethinterface.SimExtend)
	if isSim {
		chainID = big.NewInt(1337)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		txslog.Error("PrepareAuth NewKeyedTransactorWithChainID", "err", err, "chainID", chainID)
		return nil, err
	}
	auth.Value = big.NewInt(0) // in wei
	auth.GasLimit = GasLimit4Deploy
	auth.GasPrice = gasPrice

	if auth.Nonce, err = getNonce4MultiEth(transactor, client, addr2TxNonce); err != nil {
		return nil, err
	}

	return auth, nil
}

func PrepareAuthHsm(client ethinterface.EthClientSpec, keyIndex int, transactor common.Address, addr2TxNonce map[common.Address]*NonceMutex) (*bind.TransactOpts, error) {
	if nil == client {
		txslog.Error("PrepareAuth", "nil input parameter", "client", client)
		return nil, errors.New("Eth client is not configured")
	}

	ctx := context.Background()
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		txslog.Error("PrepareAuth", "Failed to SuggestGasPrice due to:", err.Error())
		return nil, errors.New("failed to get suggest gas price " + err.Error())
	}

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		txslog.Error("PrepareAuth NetworkID", "err", err)
		return nil, err
	}

	auth, err := newHSMTransactorWithChainID(keyIndex, transactor, chainID)
	if err != nil {
		txslog.Error("PrepareAuth NewKeyedTransactorWithChainID", "err", err, "chainID", chainID)
		return nil, err
	}
	auth.Value = big.NewInt(0) // in wei
	auth.GasLimit = GasLimit4Deploy
	auth.GasPrice = gasPrice

	if auth.Nonce, err = getNonce4MultiEth(transactor, client, addr2TxNonce); err != nil {
		return nil, err
	}

	return auth, nil
}

// newHSMTransactorWithChainID is a utility method to easily create a transaction signer HSM
func newHSMTransactorWithChainID(keyIndex int, from common.Address, chainID *big.Int) (*bind.TransactOpts, error) {
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}
	signer := types.LatestSignerForChainID(chainID)
	return &bind.TransactOpts{
		From: from,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != from {
				return nil, bind.ErrNotAuthorized
			}
			r, s, v, err := adapter.SignSecp256k1Msg(signer.Hash(tx).Bytes(), keyIndex)
			if err != nil {
				return nil, err
			}
			signature := adapter.MakeRSVsignature(r, s, v)
			txslog.Info("newHSMTransactorWithChainID", "signature", hex.EncodeToString(signature), "keyIndex", keyIndex)

			signtx, err := tx.WithSignature(signer, signature)
			if nil != err {
				txslog.Error("newHSMTransactorWithChainID", "signer.Sender failed due to", err.Error())
				return nil, err
			}

			return signtx, err
		},
	}, nil
}

func waitEthTxFinished(client ethinterface.EthClientSpec, txhash common.Hash, txName string) error {
	txslog.Info(txName, "Wait for tx to be finished executing with hash", txhash.String())
	timeout := time.NewTimer(PendingDuration4TxExeuction * time.Second)
	oneSecondtimeout := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-timeout.C:
			txslog.Info(txName, "tx", "eth tx timeout")
			return errors.New("eth tx timeout")
		case <-oneSecondtimeout.C:
			_, err := client.TransactionReceipt(context.Background(), txhash)
			if err == ethereum.NotFound {
				continue
			} else if err != nil {
				return err
			}
			txslog.Info(txName, "Finished executing for tx", txhash.String())
			return nil
		}
	}
}

//GetEthTxStatus ...
func GetEthTxStatus(client ethinterface.EthClientSpec, txhash common.Hash) string {
	receipt, err := client.TransactionReceipt(context.Background(), txhash)
	if nil != err {
		return EthTxPending.String()
	}
	status := EthTxStatus(receipt.Status).String()
	if status != EthTxPending.String() {
		txslog.Info("GetEthTxStatus", "Eth tx hash", txhash.String(), "status", status, "BlockNum", receipt.BlockNumber.Int64())
	}

	return status
}

func NewTransferTx(clientSpec ethinterface.EthClientSpec, from, to common.Address, input []byte, value *big.Int, addr2TxNonce map[common.Address]*NonceMutex) (*types.Transaction, error) {
	price, err := clientSpec.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	nonce, err := getNonce4MultiEth(from, clientSpec, addr2TxNonce)
	if err != nil {
		return nil, err
	}
	var gas uint64 = 21000
	if input != nil {
		//var msg ethereum.CallMsg
		//msg.To = &to
		//msg.Data = input
		//gas, err = clientSpec.EstimateGas(context.Background(), msg)
		//if err != nil {
		//	//return nil,err
		//	txslog.Error("handleLogWithdraw", "EstimateGas err", err)
		//	gas = 80000
		//}
		//实际测试"cumulativeGasUsed": "0xdc82",
		gas = uint64(80000)
	}

	ntx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce.Uint64(),
		GasPrice: price,
		To:       &to,
		Data:     input,
		Value:    value,
		Gas:      gas,
	})

	return ntx, nil
}
