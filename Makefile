.PHONY: build docker-run docker-stop format integrationtest run test proto proto-lint

define setup_env
    $(eval include $(1))
    $(eval export)
endef

proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

# proto-lint: lints protos
proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

run:
	@echo "Running introspector..."
	$(call setup_env, envs/introspector.dev.env)
	@go run cmd/introspector.go

test:
	@echo "Running unit tests..."
	@go test -v $$(go list ./... | grep -v '/test$$') github.com/ArkLabsHQ/introspector/pkg/arkade/... github.com/ArkLabsHQ/introspector/pkg/client/...

integrationtest:
	@echo "Running integration test..."
	@go test -v ./test/...

# docker-run: starts docker test environment
docker-run:
	@echo "Running dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml up --build -d

# docker-stop: tears down docker test environment
docker-stop:
	@echo "Stopping dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml down -v

build:
	@echo "Building introspector..."
	@go build -o build/introspector-$(shell go env GOOS)-$(shell go env GOARCH) cmd/introspector.go

lint:
	golangci-lint run --fix

format:
	@go fmt ./...