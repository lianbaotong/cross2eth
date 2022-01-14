package ethtxs

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"

	"github.com/lianbaotong/cross2eth/ebrelayer/utils"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/lianbaotong/cross2eth/ebrelayer/relayer/ethereum/ethinterface"

	"github.com/33cn/chain33/common/log/log15"
	"github.com/33cn/plugincgo/plugin/crypto/secp256k1hsm/adapter"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lianbaotong/cross2eth/contracts/contracts4eth/generated"
)

var (
	txslog = log15.New("ethereum relayer", "ethtxs")
)

//const ...
const (
	// GasLimit : the gas limit in Gwei used for transactions sent with TransactOpts
	GasLimit         = uint64(100 * 10000)
	GasLimit4RelayTx = uint64(40 * 10000)
	GasLimit4Deploy  = uint64(0) //此处需要设置为0,让交易自行估计,否则将会导致部署失败,TODO:其他解决途径后续调研解决
)

type TxPara2relayOracleClaim struct {
	OracleInstance *generated.Oracle
	Client         ethinterface.EthClientSpec
	Sender         common.Address
	TokenOnEth     common.Address
	Claim          ProphecyClaim
	PrivateKey     *ecdsa.PrivateKey
	Addr2TxNonce   map[common.Address]*NonceMutex
	SignViaHsm     bool
	Secp256k1Index int
}

// RelayOracleClaimToEthereum : relays the provided burn or lock to Chain33Bridge contract on the Ethereum network
func RelayOracleClaimToEthereum(txPara *TxPara2relayOracleClaim) (txhash string, err error) {
	oracleInstance := txPara.OracleInstance
	client := txPara.Client
	sender := txPara.Sender
	tokenOnEth := txPara.TokenOnEth
	claim := txPara.Claim
	privateKey := txPara.PrivateKey
	addr2TxNonce := txPara.Addr2TxNonce
	signViaHsm := txPara.SignViaHsm
	secp256k1Index := txPara.Secp256k1Index

	txslog.Info("RelayProphecyClaimToEthereum", "sender", sender.String(), "chain33Sender", hexutil.Encode(claim.Chain33Sender), "ethereumReceiver", claim.EthereumReceiver.String(),
		"TokenAddress", claim.TokenContractAddress.String(), "symbol", claim.Symbol, "Amount", claim.Amount.String(), "claimType", claim.ClaimType, "tokenOnEth", tokenOnEth.String())

	var auth *bind.TransactOpts
	if signViaHsm {
		auth, err = PrepareAuthHsm(client, secp256k1Index, sender, addr2TxNonce)
		if nil != err {
			txslog.Error("RelayProphecyClaimToEthereum", "PrepareAuthHsm err", err.Error())
			return "", err
		}
	} else {
		auth, err = PrepareAuth4MultiEthereum(client, privateKey, sender, addr2TxNonce)
		if nil != err {
			txslog.Error("RelayProphecyClaimToEthereum", "PrepareAuth err", err.Error())
			return "", err
		}
	}

	defer func() {
		if nil != err {
			_, _ = revokeNonce4MultiEth(sender, addr2TxNonce)
		}
	}()

	auth.GasLimit = GasLimit4RelayTx

	claimID := crypto.Keccak256Hash(claim.chain33TxHash, claim.Chain33Sender, claim.EthereumReceiver.Bytes(), []byte(claim.Symbol), claim.Amount.Bytes())

	// Sign the hash using the active validator's private key
	var signature []byte
	if signViaHsm {
		R, S, V, err := adapter.SignSecp256k1Hash(utils.SoliditySHA3WithPrefix(claimID[:]), secp256k1Index)
		if nil != err {
			panic("Failed to Sign Secp256k1 via HSM due to" + err.Error())
		}
		signature = adapter.MakeRSVsignature(R, S, V)
	} else {
		signature, err = utils.SignClaim4Evm(claimID, privateKey)
		if nil != err {
			return "", err
		}
	}

	txslog.Info("RelayProphecyClaimToEthereum", "sender", sender.String(), "nonce", auth.Nonce, "claim.chain33TxHash", common.Bytes2Hex(claim.chain33TxHash))

	tx, err := oracleInstance.NewOracleClaim(auth, uint8(claim.ClaimType), claim.Chain33Sender, claim.EthereumReceiver, tokenOnEth, claim.Symbol, claim.Amount, claimID, signature)
	if nil != err {
		txslog.Error("RelayProphecyClaimToEthereum", "NewOracleClaim failed due to:", err.Error())
		return "", err
	}

	txhash = tx.Hash().Hex()
	txslog.Info("RelayProphecyClaimToEthereum", "NewOracleClaim tx hash:", txhash)
	return txhash, nil
}
