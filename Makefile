BIN := tinytap

.PHONY: all generate build run run-raw test-e2e test-integration clean

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

test-e2e:
	@bash scripts/test-e2e.sh

test-integration:
	sudo go test -tags=privileged -v ./internal/loader/

clean:
	rm -f $(BIN) internal/loader/bpf/tinytap_bpf*.go internal/loader/bpf/tinytap_bpf*.o
	rm -f internal/loader/bpf/fixture/fixture_bpf*.go internal/loader/bpf/fixture/fixture_bpf*.o
