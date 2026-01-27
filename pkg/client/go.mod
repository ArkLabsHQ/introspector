module github.com/ArkLabsHQ/introspector/pkg/client

go 1.25.3

replace github.com/ArkLabsHQ/introspector/api-spec => ../../api-spec

require (
	github.com/ArkLabsHQ/introspector/api-spec v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.76.0
)

require (
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/protobuf v1.36.7 // indirect
)
