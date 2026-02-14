module github.com/ArkLabsHQ/introspector/pkg/arkade

go 1.25.7

replace github.com/arkade-os/arkd/pkg/errors => github.com/arkade-os/arkd/pkg/errors v0.0.0-20260213160542-d57655255d93

require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.0.0-20260213160542-d57655255d93
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	golang.org/x/crypto v0.43.0
	modernc.org/mathutil v1.7.1
)

require (
	github.com/arkade-os/arkd/pkg/errors v0.0.0-00010101000000-000000000000 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/sys v0.37.0 // indirect
	google.golang.org/grpc v1.76.0 // indirect
)
