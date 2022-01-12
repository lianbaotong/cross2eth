package hsm

import (
	chain33Common "github.com/33cn/chain33/common"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"fmt"
)

func Secp256k1Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secp256k1",
		Short: "import or export secp256k1 private key",
	}
	cmd.AddCommand(
		importSecp256k1KeyCmd(),
		exportSecp256k1KeyCmd(),
	)
	return cmd
}

func importSecp256k1KeyCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "import",
		Short: "import secp256k1 private key",
		Run:   importSecp256k1Key,
	}
	addImportSecp256k1KeyFlags(cmd)
	return cmd
}

func addImportSecp256k1KeyFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("key", "k", "", "private key")
	_ = cmd.MarkFlagRequired("key")
}

func importSecp256k1Key(cmd *cobra.Command, _ []string) {
	key, _ := cmd.Flags().GetString("key")
	privateKeySlice, err := chain33Common.FromHex(key)
	if nil != err {
		fmt.Println("convert string error due to:" + err.Error())
		return
	}

	if len(privateKeySlice) != 32 {
		fmt.Println("invalid priv key length", len(privateKeySlice))
		return
	}

	privateKey, err := crypto.ToECDSA(privateKeySlice)
	if nil != err {
		fmt.Println("Failed ToECDSA due to " + err.Error())
		return
	}

}

