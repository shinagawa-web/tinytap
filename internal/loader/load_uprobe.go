package loader

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"

	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
)

// ErrLibSSLNotExecutable means libsslPath exists but has no POSIX execute
// permission bit set. cilium/ebpf's link.OpenExecutable requires it, but
// distro-packaged shared libraries commonly ship without it (e.g. Debian/
// Ubuntu's libssl3 package installs libssl.so.3 as mode 0644, unlike
// libc.so.6's 0755) even though the dynamic linker itself never checks the
// mode bit. AttachSSLSetFd does not chmod the target itself — that would
// silently mutate a system library's permissions as a side effect of
// running a capture tool — so callers must fix this themselves, e.g.
// `sudo chmod +x <path>`, before retrying.
var ErrLibSSLNotExecutable = errors.New("libssl path has no execute permission bit set (try: sudo chmod +x <path>)")

// SSLFdProbe attaches a uprobe on SSL_set_fd in a target process's libssl
// and exposes a (pid, SSL*) -> fd lookup backed by a BPF hash map.
//
// This is a standalone capability (#147): it is not wired into Load() or
// the live capture loop. Deciding which pid to target is the caller's job —
// see cmd/tinytap's sslWatcher for the automatic per-pid discovery logic.
//
// Known gap: SSLFdProbe only observes fds set via the public
// SSL_set_fd(ssl, fd) API. Applications that instead build their own BIO
// via BIO_new_socket() + SSL_set_bio(ssl, bio, bio) bypass SSL_set_fd
// entirely and will never appear in Lookup — an accepted limitation (see
// #144's "Resolved questions" and #147's scope).
type SSLFdProbe struct {
	objs bpf.TinytapUprobeObjects
	link link.Link
}

// AttachSSLSetFd loads the SSL_set_fd uprobe BPF program and attaches it to
// the SSL_set_fd symbol in libsslPath.
//
// pid scopes the uprobe to a single process; pass 0 to attach system-wide
// to every process that calls into libsslPath. libsslPath is expected to
// come from internal/tls.Find — this function performs no discovery of its
// own, only attachment.
func AttachSSLSetFd(pid uint32, libsslPath string) (*SSLFdProbe, error) {
	info, err := os.Stat(libsslPath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", libsslPath, err)
	}
	if info.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("%s: %w", libsslPath, ErrLibSSLNotExecutable)
	}

	spec, err := bpf.LoadTinytapUprobe()
	if err != nil {
		return nil, fmt.Errorf("load uprobe spec: %w", err)
	}

	p := &SSLFdProbe{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("load uprobe objects: %w", err)
	}

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		_ = p.objs.Close()
		return nil, fmt.Errorf("open executable %s: %w", libsslPath, err)
	}

	lnk, err := ex.Uprobe("SSL_set_fd", p.objs.HandleSslSetFd, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		_ = p.objs.Close()
		return nil, fmt.Errorf("attach uprobe SSL_set_fd: %w", err)
	}
	p.link = lnk

	return p, nil
}

// Lookup returns the fd most recently associated with ssl via SSL_set_fd
// for pid, and whether an entry was found.
func (p *SSLFdProbe) Lookup(pid uint32, ssl uint64) (int32, bool) {
	key := bpf.TinytapUprobeSslFdKey{Pid: pid, Ssl: ssl}
	var fd int32
	if err := p.objs.SslFdMap.Lookup(&key, &fd); err != nil {
		return 0, false
	}
	return fd, true
}

// Close detaches the uprobe and releases the loaded BPF objects.
func (p *SSLFdProbe) Close() error {
	var errs []error
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close uprobe link: %w", err))
		}
	}
	if err := p.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close uprobe objects: %w", err))
	}
	return errors.Join(errs...)
}
