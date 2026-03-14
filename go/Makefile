VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
BINARY := rhg-authenticator

# Native build only — CGO required for PCSC on macOS/Linux.
# Cross-compilation is NOT supported. Use CI with native runners per platform.
.PHONY: build test vet clean checksums

build:
	@mkdir -p release
	go build -trimpath -ldflags "$(LDFLAGS)" -o release/$(BINARY) .

test:
	go test ./... -count=1

vet:
	go vet ./...

clean:
	rm -rf release/

checksums:
	@cd release && shasum -a 256 $(BINARY)* > SHA256SUMS.txt
	@echo "Checksums written to release/SHA256SUMS.txt"
