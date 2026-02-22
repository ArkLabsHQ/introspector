module github.com/ArkLabsHQ/introspector/pkg/client

go 1.25.7

replace github.com/ArkLabsHQ/introspector/api-spec => ../../api-spec

require (
	github.com/ArkLabsHQ/introspector/api-spec v0.0.0-00010101000000-000000000000
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20260220163635-76f077b0e63b
	google.golang.org/grpc v1.76.0
)

require (
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20260220163635-76f077b0e63b // indirect
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
