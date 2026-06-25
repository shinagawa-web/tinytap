BIN      := tinytap
COVFILE  := /tmp/tinytap-cover.out
FILTERED := /tmp/tinytap-cover-filtered.out

.PHONY: all generate build run run-raw check test-e2e test-integration install install-hooks clean

all: generate build

generate:
	cd internal/loader/bpf && go generate
	cd internal/loader/bpf/fixture && go generate

build:
	go build -o $(BIN) ./cmd/tinytap

run: build
	@bash scripts/demo.sh

run-raw: build
	sudo ./$(BIN) --output stdout

check:
	go test ./... -coverprofile=$(COVFILE) -covermode=atomic
	grep -vE '(_bpfel\.go|_bpfeb\.go|internal/loader/load\.go)' $(COVFILE) > $(FILTERED)
	@total=$$(go tool cover -func=$(FILTERED) | tail -1 | awk '{print $$3}'); \
	if [ "$$total" != "100.0%" ]; then \
	    echo "FAIL: coverage $$total, want 100.0%"; \
	    go tool cover -func=$(FILTERED) | grep -v '100.0%'; \
	    exit 1; \
	fi
	@echo "PASS: coverage 100.0%"

test-e2e:
	@bash scripts/test-e2e.sh

GOBIN := $(shell go env GOROOT)/bin/go

test-integration:
	sudo $(GOBIN) test -tags=privileged -v ./internal/loader/

install: install-hooks

install-hooks:
	ln -sf "$(PWD)/scripts/pre-push" $$(git rev-parse --git-common-dir)/hooks/pre-push

clean:
	rm -f $(BIN) internal/loader/bpf/tinytap_bpf*.go internal/loader/bpf/tinytap_bpf*.o
	rm -f internal/loader/bpf/fixture/fixture_bpf*.go internal/loader/bpf/fixture/fixture_bpf*.o
