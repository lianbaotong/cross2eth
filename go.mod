module github.com/lianbaotong/cross2eth

go 1.15

replace github.com/33cn/plugincgo => github.com/zhengjunhe/plugincgo v0.0.0-20220114020627-1c9875f9761c

require (
	github.com/33cn/chain33 v1.65.6-0.20211220075037-0e6ddce83502
	github.com/33cn/plugin v1.65.5-0.20211228162005-9bff4e6aa8f6
	github.com/33cn/plugincgo v0.0.0-20220106071149-9d31d191a099
	github.com/BurntSushi/toml v0.3.1
	github.com/bitly/go-simplejson v0.5.0
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/ethereum/go-ethereum v1.10.13
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.5.2
	github.com/hashicorp/golang-lru v0.5.5-0.20210104140557-80c98217689d
	github.com/pborman/uuid v1.2.0
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	github.com/tjfoc/gmsm v1.3.2
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	google.golang.org/protobuf v1.27.1
)
