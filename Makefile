.PHONY: init run

# Initialize the project from scratch
init: init-module dependencies build

# Initialize Go module and clean module cache
init-module:
	go mod init tekton-dashboard-auth
	go clean -modcache

# Build the binary
build:
	go build -o bin/tekton-dashboard-auth .

# Run the binary
run: build
	./bin/tekton-dashboard-auth

# Dependencies: Use 'go mod tidy' to clean up dependencies
dependencies:
	go mod tidy
	go get -u golang.org/x/tools/cmd/goimports
