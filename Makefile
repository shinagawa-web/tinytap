BIN := tinytap

.PHONY: all generate build run run-raw test-e2e clean

all: generate build

generate:
	cd internal/loader/bpf && go generate

build:
	go build -o $(BIN) ./cmd/tinytap

run: build
	@bash scripts/demo.sh

run-raw: build
	sudo ./$(BIN) --output stdout

test-e2e:
	@bash scripts/test-e2e.sh

clean:
	rm -f $(BIN) internal/loader/bpf/tinytap_bpf*.go internal/loader/bpf/tinytap_bpf*.o
