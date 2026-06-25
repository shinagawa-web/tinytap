BIN                := tinytap
COVERAGE_THRESHOLD ?= 100
COVFILE            := /tmp/tinytap-cover.out
FILTERED           := /tmp/tinytap-cover-filtered.out

.PHONY: all generate build run run-raw lint test check-coverage test-e2e test-integration install install-hooks clean

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

lint:
	golangci-lint run

test:
	go test ./... -coverprofile=$(COVFILE) -covermode=atomic

check-coverage:
	grep -vE '(_bpfel\.go|_bpfeb\.go|internal/loader/load\.go)' $(COVFILE) > $(FILTERED)
	@awk 'NR>1 { total+=$$2; if($$3>0) covered+=$$2 } END { \
		printf "Total coverage: %d/%d statements\n", covered, total; \
		if (covered * 100 < total * $(COVERAGE_THRESHOLD)) { \
			printf "FAIL: %d uncovered statement(s), below threshold $(COVERAGE_THRESHOLD)%%\n", total-covered; exit 1 \
		} \
	}' $(FILTERED)
	@echo "PASS: coverage $(COVERAGE_THRESHOLD)%"

test-e2e:
	@bash scripts/test-e2e.sh

GOBIN := $(shell go env GOROOT)/bin/go

test-integration:
	sudo $(GOBIN) test -tags=privileged -v ./internal/loader/

install: install-hooks

install-hooks:
	@HOOKS_DIR=$$(git rev-parse --git-path hooks); \
	mkdir -p "$$HOOKS_DIR"; \
	cp scripts/pre-push "$$HOOKS_DIR/pre-push"; \
	chmod +x "$$HOOKS_DIR/pre-push"; \
	echo "pre-push hook installed to $$HOOKS_DIR/pre-push."

clean:
	rm -f $(BIN) internal/loader/bpf/tinytap_bpf*.go internal/loader/bpf/tinytap_bpf*.o
	rm -f internal/loader/bpf/fixture/fixture_bpf*.go internal/loader/bpf/fixture/fixture_bpf*.o
