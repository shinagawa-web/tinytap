BIN := tinytap

.PHONY: all generate build run run-raw clean

all: generate build

generate:
	cd cmd/tinytap && go generate

build:
	go build -o $(BIN) ./cmd/tinytap

run: build
	@bash scripts/demo.sh

run-raw: build
	sudo ./$(BIN)

clean:
	rm -f $(BIN) cmd/tinytap/tinytap_bpf*.go cmd/tinytap/tinytap_bpf*.o
