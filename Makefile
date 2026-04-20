VERSION := $(shell git describe --tags --exact-match 2>/dev/null || echo "$(shell git rev-parse --abbrev-ref HEAD)@$(shell git rev-parse --short HEAD)")
LDFLAGS := -ldflags "-X github.com/xiongjiwei/mcp-ssh/cmd.Version=$(VERSION)"

.PHONY: build install

build:
	go build $(LDFLAGS) -o mcp-ssh .

install:
	go install $(LDFLAGS) .
