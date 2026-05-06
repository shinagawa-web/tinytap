BIN     := tinytap
VMLINUX := bpf/vmlinux.h

.PHONY: all generate build run clean

all: generate build

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: $(VMLINUX)
	cd cmd/tinytap && go generate

build:
	go build -o $(BIN) ./cmd/tinytap

run:
	sudo ./$(BIN)

clean:
	rm -f $(BIN) cmd/tinytap/tinytap_bpf*.go cmd/tinytap/tinytap_bpf*.o $(VMLINUX)
