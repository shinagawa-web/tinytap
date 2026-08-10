//go:build !amd64 && !arm64

package loader

import (
	"log"
	"runtime"
)

func (tt *Tinytap) tryAttachKprobe() {
	log.Printf("tinytap: kprobe sendfile payload capture is arm64/amd64-only, skipping on %s", runtime.GOARCH)
}
