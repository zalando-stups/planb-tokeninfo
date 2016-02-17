SHELL := /bin/bash

GOOS ?= linux
GOARCH ?= amd64

SOURCES = $(shell find $(ROOT_DIR) -name "*.go")
TARGET = build/planb-tokeninfo

.PHONY: all fmt test clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	go build \
		-o $(TARGET) \
		github.com/zalando/planb-tokeninfo

fmt:
	@go fmt ./...

test:
	go test -timeout=5s github.com/zalando/planb-tokeninfo/...

clean:
	@rm -f $(TARGET)
