BIN := tinytap

.PHONY: all generate build run clean

all: generate build

generate:
	cd cmd/tinytap && go generate

build:
	go build -o $(BIN) ./cmd/tinytap

run:
	sudo ./$(BIN)

clean:
	rm -f $(BIN) cmd/tinytap/tinytap_bpf*.go cmd/tinytap/tinytap_bpf*.o
