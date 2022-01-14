package chain33

import (
	goSDKSh256 "crypto/sha256"
	"fmt"
	chain33Common "github.com/33cn/chain33/common"
	chain33Address "github.com/33cn/chain33/common/address"
	chain33EVMCrypto "github.com/33cn/plugin/plugin/dapp/evm/executor/vm/common/crypto"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
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


//hash=8bf66a85df72bb12c22cbb07ca12421ac711ce95cbaa7840caa9900b50b32b6b signature=261aeec4ad0c87a2c2d05e73727cfc46ab26ce0f318e2ae2d091ff8c19f56951f5807dbe6daa8b3c95efbb4bb831f5f25008d74e7850cb291b1c4238a386a04200 keyIndex=21
//hash=2073345795e50293942e4595635ec05fb4e9fffa63d8c2108093780550d9fe9d signature=24ff72f630a5d824c1f7974d58c357b13649ded35ddee72716b36ca9d5db515290117bcb707f06ef6e21c8bbcf2b99aa3307707e4c7ababb563100ceadf8913c01 keyIndex=22
//hash=1b688d645dd4704b854ec22a8c34cd94e656f5f3bec4189aedbb270f78053208 signature=400b6f4716e54c665611ce16abb22649a4e8528cfeb855c06dde346d36aeabd1b300e6edff62d48a32c5ec9569d2303cbe61f64c731ba8e18dbf7925596c75e201 keyIndex=23
//hash=47b6522a48a8adb6619fb3404adbaedf048dc4273ce20189364702caa02140ee signature=94bc00adce254a0bc2c8ee61497b9ce753ea59edc8b66d536fa8365b386a972fdf901e4116d8e6d12e5e0491ded86af190c46192ad9133bfa3ed7dc9a8457db601 keyIndex=24


func Test_RecoverEthereumAddress(t *testing.T) {
	//sig, _ := chain33Common.FromHex("261aeec4ad0c87a2c2d05e73727cfc46ab26ce0f318e2ae2d091ff8c19f56951f5807dbe6daa8b3c95efbb4bb831f5f25008d74e7850cb291b1c4238a386a04200")
	//hash, _ := chain33Common.FromHex("8bf66a85df72bb12c22cbb07ca12421ac711ce95cbaa7840caa9900b50b32b6b")
	sig, _ := chain33Common.FromHex("24ff72f630a5d824c1f7974d58c357b13649ded35ddee72716b36ca9d5db515290117bcb707f06ef6e21c8bbcf2b99aa3307707e4c7ababb563100ceadf8913c01")
	hash, _ := chain33Common.FromHex("2073345795e50293942e4595635ec05fb4e9fffa63d8c2108093780550d9fe9d")
	pubRecoverd, err := ethCrypto.Ecrecover(hash[:], sig)
	assert.Equal(t, nil, err)
	fmt.Println(" pubRecoverd is ", chain33Common.ToHex(pubRecoverd))
	secpPubKey, err := ethCrypto.UnmarshalPubkey(pubRecoverd)
	if nil != err {
		panic("ethCrypto.UnmarshalPubkey failed")
	}
	recoveredAddr := ethCrypto.PubkeyToAddress(*secpPubKey)
	fmt.Println(" recoveredAddr Ethereum is ", recoveredAddr.String())
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

