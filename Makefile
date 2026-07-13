BINARY_NAME=403bypasser
VERSION=1.2
LDFLAGS=-ldflags="-s -w"

all: build

deps:
	@echo "Checking dependencies..."
	go mod tidy
	@echo "Dependencies installed."

build: deps
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) .
	@echo "Build complete: ./bin/$(BINARY_NAME)"

install: build
	@echo "Installing to system..."
	sudo mv bin/$(BINARY_NAME) /usr/local/bin/
	@echo "SUCCESS! You can now run '$(BINARY_NAME)' from anywhere!"

release: deps
	@echo "Building release binaries for v$(VERSION)..."
	@mkdir -p dist
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64  .
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64  .
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64   .
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64   .
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Release binaries ready in ./dist/"

clean:
	@echo "Cleaning..."
	rm -rf bin dist
	rm -f results.txt
