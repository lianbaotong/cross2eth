package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/33cn/plugincgo/plugin/crypto/secp256k1hsm/adapter"

	"github.com/33cn/chain33/common"
	dbm "github.com/33cn/chain33/common/db"
	logf "github.com/33cn/chain33/common/log"
	"github.com/33cn/chain33/common/log/log15"
	chain33Types "github.com/33cn/chain33/types"
	tml "github.com/BurntSushi/toml"
	"github.com/btcsuite/btcd/limits"
	"github.com/lianbaotong/cross2eth/ebrelayer/relayer"
	chain33Relayer "github.com/lianbaotong/cross2eth/ebrelayer/relayer/chain33"
	ethRelayer "github.com/lianbaotong/cross2eth/ebrelayer/relayer/ethereum"
	"github.com/lianbaotong/cross2eth/ebrelayer/relayer/events"
	ebrelayerTypes "github.com/lianbaotong/cross2eth/ebrelayer/types"
	relayerTypes "github.com/lianbaotong/cross2eth/ebrelayer/types"
)

var (
	configPath = flag.String("f", "", "configfile")
	versionCmd = flag.Bool("s", false, "version")
	//IPWhiteListMap ...
	IPWhiteListMap = make(map[string]bool)
	mainlog        = log15.New("relayer manager", "main")
)

func main() {
	flag.Parse()
	if *versionCmd {
		fmt.Println(relayerTypes.Version4Relayer)
		return
	}
	if *configPath == "" {
		*configPath = "relayer.toml"
	}

	err := os.Chdir(pwd())
	if err != nil {
		panic(err)
	}
	d, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	mainlog.Info("current dir:", "dir", d)
	err = limits.SetLimits()
	if err != nil {
		panic(err)
	}
	cfg := initCfg(*configPath)
	mainlog.Info("Starting FUZAMEI Chain33-X-Ethereum relayer software:", "\n     Name: ", cfg.Title)
	logf.SetFileLog(convertLogCfg(cfg.Log))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	mainlog.Info("db info:", " Dbdriver = ", cfg.Dbdriver, ", DbPath = ", cfg.DbPath, ", DbCache = ", cfg.DbCache)

	db := dbm.NewDB("relayer_db_service", cfg.Dbdriver, cfg.DbPath, cfg.DbCache)

	ethRelayerCnt := len(cfg.EthRelayerCfg)
	chain33MsgChan2Eths := make(map[string]chan<- *events.Chain33Msg)
	ethBridgeClaimChan := make(chan *ebrelayerTypes.EthBridgeClaim, 100)

	//?????????????????????????????????
	ethRelayerServices := make(map[string]*ethRelayer.Relayer4Ethereum)
	for i := 0; i < ethRelayerCnt; i++ {
		chain33MsgChan := make(chan *events.Chain33Msg, 100)
		chain33MsgChan2Eths[cfg.EthRelayerCfg[i].EthChainName] = chain33MsgChan

		ethStartPara := &ethRelayer.EthereumStartPara{
			DbHandle:           db,
			EthProvider:        cfg.EthRelayerCfg[i].EthProvider,
			EthProviderHttp:    cfg.EthRelayerCfg[i].EthProviderCli,
			BridgeRegistryAddr: cfg.EthRelayerCfg[i].BridgeRegistry,
			Degree:             cfg.EthRelayerCfg[i].EthMaturityDegree,
			BlockInterval:      cfg.EthRelayerCfg[i].EthBlockFetchPeriod,
			EthBridgeClaimChan: ethBridgeClaimChan,
			Chain33MsgChan:     chain33MsgChan,
			ProcessWithDraw:    cfg.ProcessWithDraw,
			Name:               cfg.EthRelayerCfg[i].EthChainName,
			ValidatorAddr:      cfg.EthereumValidator,
			SignViaHsm:         cfg.SignViaHsm,
			Secp256k1Index:     int(cfg.Secp256K1KeyIndex4Eth),
		}
		ethRelayerService := ethRelayer.StartEthereumRelayer(ethStartPara)
		ethRelayerServices[ethStartPara.Name] = ethRelayerService
	}

	//??????chain33?????????
	chain33StartPara := &chain33Relayer.Chain33StartPara{
		ChainName:          cfg.Chain33RelayerCfg.ChainName,
		Ctx:                ctx,
		SyncTxConfig:       cfg.Chain33RelayerCfg.SyncTxConfig,
		BridgeRegistryAddr: cfg.Chain33RelayerCfg.BridgeRegistryOnChain33,
		DBHandle:           db,
		EthBridgeClaimChan: ethBridgeClaimChan,
		Chain33MsgChan:     chain33MsgChan2Eths,
		ChainID:            cfg.Chain33RelayerCfg.ChainID4Chain33,
		ProcessWithDraw:    cfg.ProcessWithDraw,
		SignViaHsm:         cfg.SignViaHsm,
		Secp256k1Index:     int(cfg.Secp256K1KeyIndex4Chain33),
	}
	if cfg.SignViaHsm {
		if cfg.Secp256K1KeyIndex4Eth < 1 || cfg.Secp256K1KeyIndex4Eth > 64 {
			panic("Invalid Secp256K1 Key index for Ethereum")
		}
		if cfg.Secp256K1KeyIndex4Chain33 < 1 || cfg.Secp256K1KeyIndex4Chain33 > 64 {
			panic("Invalid Secp256K1 Key index for HSM")
		}
		if 0 == len(cfg.Chain33PubKey) {
			panic("No Public key is configured ")
		}
		chain33StartPara.Chain33PubKey, _ = common.FromHex(cfg.Chain33PubKey)
		if err := adapter.OpenHSMSession(); nil != err {
			panic("Failed to Open HSM Session due to" + err.Error())
		}
		mainlog.Info("Succeed to Open HSM Session")
	}
	chain33RelayerService := chain33Relayer.StartChain33Relayer(chain33StartPara)
	relayerManager := relayer.NewRelayerManager(chain33RelayerService, ethRelayerServices, db)

	mainlog.Info("ebrelayer", "cfg.JrpcBindAddr = ", cfg.JrpcBindAddr)
	startRPCServer(cfg.JrpcBindAddr, relayerManager)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
		wg.Wait()
		if cfg.SignViaHsm {
			_ = adapter.ReleaeAccessRight(int(cfg.Secp256K1KeyIndex4Eth))
			_ = adapter.ReleaeAccessRight(int(cfg.Secp256K1KeyIndex4Chain33))
			_ = adapter.CloseHSMSession()
		}

		os.Exit(0)
	}()
}

func convertLogCfg(log *relayerTypes.Log) *chain33Types.Log {
	return &chain33Types.Log{
		Loglevel:        log.Loglevel,
		LogConsoleLevel: log.LogConsoleLevel,
		LogFile:         log.LogFile,
		MaxFileSize:     log.MaxFileSize,
		MaxBackups:      log.MaxBackups,
		MaxAge:          log.MaxAge,
		LocalTime:       log.LocalTime,
		Compress:        log.Compress,
		CallerFile:      log.CallerFile,
		CallerFunction:  log.CallerFunction,
	}
}

func pwd() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	return dir
}

func initCfg(path string) *relayerTypes.RelayerConfig {
	var cfg relayerTypes.RelayerConfig
	if _, err := tml.DecodeFile(path, &cfg); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	//fmt.Println(cfg)
	return &cfg
}

//IsIPWhiteListEmpty ...
func IsIPWhiteListEmpty() bool {
	return len(IPWhiteListMap) == 0
}

//IsInIPWhitelist ??????ipAddr?????????ip??????????????????
func IsInIPWhitelist(ipAddrPort string) bool {
	ipAddr, _, err := net.SplitHostPort(ipAddrPort)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipAddr)
	if ip.IsLoopback() {
		return true
	}
	if _, ok := IPWhiteListMap[ipAddr]; ok {
		return true
	}
	return false
}

//RPCServer ...
type RPCServer struct {
	*rpc.Server
}

//ServeHTTP ...
func (r *RPCServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	mainlog.Info("ServeHTTP", "request address", req.RemoteAddr)
	if !IsIPWhiteListEmpty() {
		if !IsInIPWhitelist(req.RemoteAddr) {
			mainlog.Info("ServeHTTP", "refuse connect address", req.RemoteAddr)
			w.WriteHeader(401)
			return
		}
	}
	r.Server.ServeHTTP(w, req)
}

//HandleHTTP ...
func (r *RPCServer) HandleHTTP(rpcPath, debugPath string) {
	http.Handle(rpcPath, r)
}

//HTTPConn ...
type HTTPConn struct {
	in  io.Reader
	out io.Writer
}

//Read ...
func (c *HTTPConn) Read(p []byte) (n int, err error) { return c.in.Read(p) }

//Write ...
func (c *HTTPConn) Write(d []byte) (n int, err error) { return c.out.Write(d) }

//Close ...
func (c *HTTPConn) Close() error { return nil }

func startRPCServer(address string, api interface{}) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("??????????????????????????????????????????")
		panic(err)
	}
	srv := &RPCServer{rpc.NewServer()}
	_ = srv.Server.Register(api)
	srv.HandleHTTP(rpc.DefaultRPCPath, rpc.DefaultDebugPath)
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			serverCodec := jsonrpc.NewServerCodec(&HTTPConn{in: r.Body, out: w})
			w.Header().Set("Content-type", "application/json")
			w.WriteHeader(200)
			err := srv.ServeRequest(serverCodec)
			if err != nil {
				mainlog.Debug("http", "Error while serving JSON request: %v", err)
				return
			}
		}
	})
	_ = http.Serve(listener, handler)
}
