.PHONY: help
help: ## print this help message
	@cat $(MAKEFILE_LIST) | grep -E '^[a-zA-Z_-//]+:.*?## .*$$' | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## tidy module dependencies and format all .go files
	go mod tidy
	go mod verify
	go fmt ./...

.PHONY: audit 
audit: ## run quality control checks
	go mod tidy --diff
	go mod verify
	go vet ./...
	go test -race -vet=off ./...

.PHONY: build/client
build/client: ## build the Caldera payload (gems-client) for multiple architectures
	env GOOS=linux GOARCH=amd64 go build -C ./cmd/client -o ./bin/gems-client
	env GOOS=linux GOARCH=arm64 go build -C ./cmd/client -o ./bin/gems-client_arm
	env GOOS=windows GOARCH=amd64 go build -C ./cmd/client -o ./bin/gems-client.exe
	env GOOS=darwin GOARCH=arm64 go build -C ./cmd/client -o ./bin/gems-client_darwin

.PHONY: build/server
build/server: ## build the GEMS server for the host architecture
	go build -C ./cmd/server -o ./bin/gems-server
