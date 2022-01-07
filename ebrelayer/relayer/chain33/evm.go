package chain33

import (
	"strings"

	"github.com/lianbaotong/cross2eth/ebrelayer/relayer/events"

	"github.com/ethereum/go-ethereum/accounts/abi"
	chain33Evm "github.com/lianbaotong/cross2eth/contracts/contracts4chain33/generated"
)

func (relayer *Relayer4Chain33) prePareSubscribeEvent() {
	var eventName string
	contractABI, err := abi.JSON(strings.NewReader(chain33Evm.BridgeBankABI))
	if err != nil {
		panic(err)
	}

	eventName = events.Chain33EventLogLock.String()
	relayer.bridgeBankEventLockSig = contractABI.Events[eventName].ID.Hex()
	eventName = events.Chain33EventLogBurn.String()
	relayer.bridgeBankEventBurnSig = contractABI.Events[eventName].ID.Hex()
	eventName = events.Chain33EventLogWithdraw.String()
	relayer.bridgeBankEventWithdrawSig = contractABI.Events[eventName].ID.Hex()

	relayer.bridgeBankAbi = contractABI

	relayerLog.Info("prePareSubscribeEvent", "bridgeBankEventLockSig", relayer.bridgeBankEventLockSig,
		"bridgeBankEventBurnSig", relayer.bridgeBankEventBurnSig, "bridgeBankEventWithdrawSig", relayer.bridgeBankEventWithdrawSig)
}
