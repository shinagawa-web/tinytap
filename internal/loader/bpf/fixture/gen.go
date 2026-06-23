// Package fixture holds the bpf2go-generated bindings for the integration-test
// fixture program in fixture.bpf.c. The generated files are checked in
// alongside this file; regenerate with `go generate` after editing the C source.
package fixture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir . -go-package fixture Fixture fixture.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
