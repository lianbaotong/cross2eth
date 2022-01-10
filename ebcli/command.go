// Copyright Fuzamei Corp. 2018 All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"fmt"
	chain33Common "github.com/33cn/chain33/common"
	"github.com/33cn/chain33/rpc/jsonclient"
	rpctypes "github.com/33cn/chain33/rpc/types"
	"github.com/33cn/chain33/system/crypto/sm2"
	"github.com/ethereum/go-ethereum/common"
	relayerTypes "github.com/lianbaotong/cross2eth/ebrelayer/types"
	"github.com/spf13/cobra"
	gmsm2 "github.com/tjfoc/gmsm/sm2"
	gmsm4 "github.com/tjfoc/gmsm/sm4"
	"math/big"
)

// SetPwdCmd set password
func SetPwdCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set_pwd",
		Short: "Set password",
		Run:   setPwd,
	}
	addSetPwdFlags(cmd)
	return cmd
}

func addSetPwdFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("password", "p", "", "password,[8-30]letter and digit")
	cmd.MarkFlagRequired("password")
}

func setPwd(cmd *cobra.Command, args []string) {
	rpcLaddr, _ := cmd.Flags().GetString("rpc_laddr")
	newPwd, _ := cmd.Flags().GetString("password")
	params := relayerTypes.ReqSetPasswd{
		Passphase: newPwd,
	}
	var res rpctypes.Reply
	ctx := jsonclient.NewRPCCtx(rpcLaddr, "Manager.SetPassphase", params, &res)
	ctx.Run()
}

// ChangePwdCmd set password
func ChangePwdCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "change_pwd",
		Short: "Change password",
		Run:   changePwd,
	}
	addChangePwdFlags(cmd)
	return cmd
}

func addChangePwdFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("old", "o", "", "old password")
	cmd.MarkFlagRequired("old")

	cmd.Flags().StringP("new", "n", "", "new password,[8-30]letter and digit")
	cmd.MarkFlagRequired("new")
}

func changePwd(cmd *cobra.Command, args []string) {
	rpcLaddr, _ := cmd.Flags().GetString("rpc_laddr")
	oldPwd, _ := cmd.Flags().GetString("old")
	newPwd, _ := cmd.Flags().GetString("new")
	params := relayerTypes.ReqChangePasswd{
		OldPassphase: oldPwd,
		NewPassphase: newPwd,
	}
	var res rpctypes.Reply
	ctx := jsonclient.NewRPCCtx(rpcLaddr, "Manager.ChangePassphase", params, &res)
	ctx.Run()
}

// LockCmd lock the relayer manager
func LockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock relayer manager",
		Run:   lock,
	}
	return cmd
}

func lock(cmd *cobra.Command, args []string) {
	rpcLaddr, _ := cmd.Flags().GetString("rpc_laddr")
	var res rpctypes.Reply
	ctx := jsonclient.NewRPCCtx(rpcLaddr, "Manager.Lock", nil, &res)
	ctx.Run()
}

// UnlockCmd unlock the wallet
func UnlockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock relayer manager",
		Run:   unLock,
	}
	addUnlockFlags(cmd)
	return cmd
}

func addUnlockFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("pwd", "p", "", "password needed to unlock")
	cmd.MarkFlagRequired("pwd")
}

func unLock(cmd *cobra.Command, args []string) {
	rpcLaddr, _ := cmd.Flags().GetString("rpc_laddr")
	pwd, _ := cmd.Flags().GetString("pwd")

	params := pwd
	var res rpctypes.Reply
	ctx := jsonclient.NewRPCCtx(rpcLaddr, "Manager.Unlock", params, &res)
	ctx.Run()
}

func sm2Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sm2",
		Short: "generate sm2 key and decrypt",
		Args:  cobra.MinimumNArgs(1),
	}
	cmd.AddCommand(
		createSm2Cmd(),
		decryptWithSm2Cmd(),
		encryptWithSm2Cmd(),
	)
	return cmd
}

func createSm2Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create sm2 key",
		Run:   createSm2Key,
	}
	return cmd
}

func createSm2Key(cmd *cobra.Command, args []string) {
	privateKey, err := gmsm2.GenerateKey()
	if nil != err {
		fmt.Println("gmsm2.GenerateKeyfailed due to:" + err.Error())
		return
	}

	pub := sm2.SerializePublicKey(&privateKey.PublicKey, false)
	pri := sm2.SerializePrivateKey(privateKey)
	pub = pub[1:]
	fmt.Println("sm2 public  key = " + common.Bytes2Hex(pub), "len = ", len(pub))
	fmt.Println("sm2 private key = " + common.Bytes2Hex(pri), "len = ", len(pri))
}

func decryptWithSm2Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decipher",
		Short: "decipher with sm2 to recover privake key",
		Run:   decryptWithSm2,
	}
	addDecryptWithSm2Flags(cmd)
	return cmd
}

func addDecryptWithSm2Flags(cmd *cobra.Command) {
	cmd.Flags().StringP("sm2key", "k", "", "sm2 private key")
	_ = cmd.MarkFlagRequired("sm2key")

	cmd.Flags().StringP("symmKeyCipher", "s", "", "symmKey Ciphered by random sm4 key, will be prefixed by 0x04 automatically")
	_ = cmd.MarkFlagRequired("symmKeyCipher")

	cmd.Flags().StringP("cipher", "c", "", "ciphered text from private key")
	_ = cmd.MarkFlagRequired("cipher")
}

func decryptWithSm2(cmd *cobra.Command, args []string) {
	sm2keyStr, _ := cmd.Flags().GetString("sm2key")
	cipherStr, _ := cmd.Flags().GetString("cipher")
	symmKeyCipherStr, _ := cmd.Flags().GetString("symmKeyCipher")

	//第一步，解密数字信封
	sm2key, err := chain33Common.FromHex(sm2keyStr)
	if nil != err {
		fmt.Println("chain33Common.FromHex failed due to:" + err.Error())
		return
	}
	if 32 != len(sm2key) {
		fmt.Println("Wrong sm2key length", len(sm2key))
		return

	}

	curve := gmsm2.P256Sm2()
	x, y := curve.ScalarBaseMult(sm2key)
	sm2Priv := &gmsm2.PrivateKey{
		PublicKey: gmsm2.PublicKey{
			Curve: gmsm2.P256Sm2(),
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(sm2key),
	}

	symmKeyCipher, err := chain33Common.FromHex(symmKeyCipherStr)
	if nil != err {
		fmt.Println("chain33Common.FromHex failed for cipher due to:" + err.Error())
		return
	}
	symmKeyCipher = append([]byte{0x04}, symmKeyCipher...)
	sm4Key, err := sm2Priv.Decrypt(symmKeyCipher)
	if nil != err {
		fmt.Println("sm2 decrypt failed due to:" + err.Error())
		return
	}
	fmt.Println("The decrypted sm4 key is:"+chain33Common.ToHex(sm4Key), "len:", len(sm4Key))
	//第二步，通过数字信封中的对称密钥，进行sm4对称解密
	sm4Cihpher, err := gmsm4.NewCipher(sm4Key)
	if err != nil {
		fmt.Println("gmsm4.NewCipher failed due to:" + err.Error())
		return
	}

	cipher, err := chain33Common.FromHex(cipherStr)
	if nil != err {
		fmt.Println("chain33Common.FromHex failed for cipher due to:" + err.Error())
		return
	}
	dst := make([]byte, 32)
	sm4Cihpher.Decrypt(dst, cipher)
	sm4Cihpher.Decrypt(dst[16:], cipher[16:])
	fmt.Println(chain33Common.ToHex(dst))
}

func encryptWithSm2Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encipher",
		Short: "encipher with sm2 to encipher privake key",
		Run:   encryptWithSm2,
	}
	addEncryptWithSm2Flags(cmd)
	return cmd
}

func addEncryptWithSm2Flags(cmd *cobra.Command) {
	cmd.Flags().StringP("sm2key", "t", "", "sm2 private key to encrypt sm4 key")
	_ = cmd.MarkFlagRequired("sm2key")

	cmd.Flags().StringP("sm4key", "f", "", "sm4 symmKey, will be prefixed by 0x04 automatically")
	_ = cmd.MarkFlagRequired("sm4key")

	cmd.Flags().StringP("key", "k", "", "private key to be encrypted")
	_ = cmd.MarkFlagRequired("key")
}

func encryptWithSm2(cmd *cobra.Command, args []string) {
	sm2keyStr, _ := cmd.Flags().GetString("sm2key")
	privatKeyStr, _ := cmd.Flags().GetString("key")
	symmKeyCipher, _ := cmd.Flags().GetString("sm4key")
	sm4Key, err := chain33Common.FromHex(symmKeyCipher)
	if nil != err {
		fmt.Println("chain33Common.FromHex failed for cipher due to:" + err.Error())
		return
	}

	gmsm4.WriteKeyToPem("key.pem", sm4Key, nil)
	sm4Key, err = gmsm4.ReadKeyFromPem("key.pem", nil)

	//第一步，通过数字信封中的对称密钥，进行sm4对称加密
	sm4Cihpher, err := gmsm4.NewCipher(sm4Key)
	if err != nil {
		fmt.Println("gmsm4.NewCipher failed due to:" + err.Error())
		return
	}

	privatKey, err := chain33Common.FromHex(privatKeyStr)
	if nil != err {
		fmt.Println("chain33Common.FromHex failed for cipher due to:" + err.Error())
		return
	}
	dst := make([]byte, 32)
	sm4Cihpher.Encrypt(dst, privatKey)
	sm4Cihpher.Encrypt(dst[16:], privatKey[16:])
	fmt.Println("The encrypted privated key:" + common.Bytes2Hex(dst), "len:", len(dst))

	//第二步，加密数字信封
	sm2key, err := chain33Common.FromHex(sm2keyStr)
	if nil != err {
		fmt.Println("chain33Common.FromHex failed due to:" + err.Error())
		return
	}
	if 32 != len(sm2key) {
		fmt.Println("Wrong sm2key length", len(sm2key))
		return

	}

	curve := gmsm2.P256Sm2()
	x, y := curve.ScalarBaseMult(sm2key)
	sm2Priv := &gmsm2.PrivateKey{
		PublicKey: gmsm2.PublicKey{
			Curve: gmsm2.P256Sm2(),
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(sm2key),
	}

	sm4Key, err = sm2Priv.Encrypt(sm4Key)
	if nil != err {
		fmt.Println("sm2 Encrypt failed due to:" + err.Error())
		return
	}
	sm4Key = sm4Key[1:]

	fmt.Println("The encrypted sm4 key:" + common.Bytes2Hex(sm4Key), "len:", len(sm4Key))
}

//sm2 public  key = 04df88444bb03100ae594bf09857e2f9183cf9d2aa6b5287282b17fa2f88d3d0bc6ecc3b6074e09b65c876257d22581bd6e68c4628b9d4edc6479a8ab733d0bbc4
//sm2 private key = 1cca3f93369cf987637d856169e13f0f623be4637e2dbf46040b14d15a8a4ada

//请输入SM2的保护私钥: 1cca3f93369cf987637d856169e13f0f623be4637e2dbf46040b14d15a8a4ada
//请输入随机对称密钥: 1d8ce8adb198a8a370d53f0a3d844d5456dfa8dbf858ebcbe93bb31fca166d3b2ab7bacb2450f943b8453ca0dc5474451afd81e6b1f2e2313d22e3506cc93a656a740678e092bd71bf967fb09fae58033cd8aa87cd925362f54115cf070abb8d3a91797b9c88e5c2509afb09d17fe2d6
//请输入要导入的公钥: 504fa1c28caaf1d5a20fefb87c50a49724ff401043420cb3ba271997eb5a43879f2f7508d37165db9d9721b819ccaa3ef08a20bbab986c18b79d44a7e4201b8e
//请输入要导入的私钥: c497234d2eab47d5cc96fa174e8d9ef7417bfc045d4ad8a87697c48a16282ff9
//请输入要导入密钥的类型：2-SM2，3-ECC_SECP_256R1, 4-RSA, 8-ECC_SECP_256K1: 8
//请输入要导入密钥的索引：9


//sm2 key=
//Function [TassCtlGenerateKey] run success
//sk_keyLen = 32, sk_key = A1DC40596A7D45FCFDB3569222AB9AA0BF80E87CEE21DE06EBB34D1DB6891DAB
//明文私钥　= 0x546563941bdd7639179c5f272bfbb708e53dc92245791c9f1ec1a9fb8674a4eb
//pk_kcvLen = 64, pk_kcv = 3744522891E6216AB8DAFF91598F361987FFEB907CCDD040815471F89AE179E2BBECDBB9E5FD1FAE8F8601F58A73E4D91213D6576F72B5A69D68F352ADFD00AF


//504fa1c28caaf1d5a20fefb87c50a49724ff401043420cb3ba271997eb5a43879f2f7508d37165db9d9721b819ccaa3ef08a20bbab986c18b79d44a7e4201b8e



