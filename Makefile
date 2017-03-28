SHELL := /bin/bash

GOOS ?= linux
GOARCH ?= amd64

SOURCES = $(shell find $(ROOT_DIR) -name "*.go")
TARGET = build/planb-tokeninfo
VERSION ?= latest

.PHONY: all fmt vet lint goimports check test clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	@echo "Building version $(VERSION).."
	go build \
		-ldflags "-s -X main.version=$(VERSION)" \
		-o $(TARGET) \
		github.com/zalando/planb-tokeninfo

fmt:
	@go fmt ./...

vet:
	@go vet ./...

lint:
	@golint ./...

goimports:
	@goimports ./...

check: fmt vet lint

test:
	go test -timeout=5s github.com/zalando/planb-tokeninfo/...

clean:
	@rm -f $(TARGET)
