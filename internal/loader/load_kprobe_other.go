//go:build !amd64 && !arm64

package loader

import (
	"log"
	"runtime"
)

// tryAttachKprobe is a no-op on architectures other than amd64 and arm64.
// The sendfile page->VA derivation only supports those two arches, and the
// bpf2go-generated kprobe bindings are not built for any other GOARCH, so
// referencing them here would break cross-compilation.  sendfile events still
// work everywhere — they just carry no payload bytes on these arches.
func (tt *Tinytap) tryAttachKprobe() {
	log.Printf("tinytap: kprobe sendfile payload capture is arm64/amd64-only, skipping on %s", runtime.GOARCH)
}
