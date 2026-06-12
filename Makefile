BIN := tinytap

.PHONY: all generate build run run-raw clean

all: generate build

generate:
	cd internal/loader/bpf && go generate

build:
	go build -o $(BIN) ./cmd/tinytap

run: build
	@bash scripts/demo.sh

run-raw: build
	sudo ./$(BIN) --no-tui

clean:
	rm -f $(BIN) internal/loader/bpf/tinytap_bpf*.go internal/loader/bpf/tinytap_bpf*.o
