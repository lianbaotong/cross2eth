package chain33

import (
	goSDKSh256 "crypto/sha256"
	"fmt"
	chain33Common "github.com/33cn/chain33/common"
	chain33Address "github.com/33cn/chain33/common/address"
	chain33EVMCrypto "github.com/33cn/plugin/plugin/dapp/evm/executor/vm/common/crypto"
	"github.com/lianbaotong/cross2eth/ebrelayer/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_RecoverChain33Address(t *testing.T) {
	claimID, _ := chain33Common.FromHex("ed06dbec047761f0c945d2b3b97d3b378fba824e81a64fe39a2090f7fb8b37ba")
	sig, _ := chain33Common.FromHex("bd8a162fd18c468eca1d9a3d757b3d90cb19e2727f4fc7004958ed479455c8da17d1a0e2516e7f749340dd5710685fc4f3a2410ed6f62ec385fe4f2512f8c6d301")
	hash := goSDKSh256.Sum256(utils.SoliditySHA3WithPrefix(claimID[:]))
	pubkey, err := chain33EVMCrypto.Ecrecover(hash[:], sig)
	assert.Equal(t, nil, err)
	address := chain33Address.PubKeyToAddr(pubkey)
	fmt.Println("address="+address)
	assert.Equal(t, "1N6HstkyLFS8QCeVfdvYxx1xoryXoJtvvZ", address)
}

//parameter := fmt.Sprintf("newOracleClaim(%d, %s, %s, %s, %s, %s, %s, %s)",
//claim.ClaimType,
//claim.EthereumSender,
//claim.Chain33Receiver,
//tokenAddr,
//claim.Symbol,
//claim.Amount,
//claimID.String(),
//common.ToHex(signature))
//
//
//
//newOracleClaim(2,
//	0xbc333839E37bc7fAAD0137aBaE2275030555101f,
//	12qyocayNF7Lv6C9qW4avxs2E7U41fKSfv,
//	1PsLhX1VcnAwJJBBJfnEthyobXEuSnTnNU,
//	ETH, 200000,
//	0xed06dbec047761f0c945d2b3b97d3b378fba824e81a64fe39a2090f7fb8b37ba,
//	0xbd8a162fd18c468eca1d9a3d757b3d90cb19e2727f4fc7004958ed479455c8da17d1a0e2516e7f749340dd5710685fc4f3a2410ed6f62ec385fe4f2512f8c6d301)

