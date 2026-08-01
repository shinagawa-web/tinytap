#!/usr/bin/env bash
# End-to-end test: starts tinytap and python http.server, fires known HTTP
# requests, and asserts the captured output matches expected patterns.
# Runs tinytap itself unprivileged, granted capabilities via setcap (see
# docs/capabilities.md — the TLS scenario below needs cap_sys_admin in
# addition to cap_dac_read_search/cap_perfmon/cap_bpf) rather than under
# sudo — sudo is still used for the one-off setcap call and the libssl
# chmod below, both of which mutate files outside this script's own process.
#
# Scenarios:
#   1. Normal: GET / HEAD / POST against python http.server → paired lines.
#   2. Abandoned: slow server killed mid-request → ABANDONED line in output.
#   3. Sendfile: GET a static file served via http.ServeFile (sendfile(2))
#      → pairs regardless of GOARCH; the payload-capture kprobe attaches on
#      arm64 and amd64 (#112), and only logs a "skipping" line on other arches.
#   4. Writev: GET against a server that calls writev(2) directly with two
#      iovecs (headers, body) → exercises the #111 multi-iovec sampling path
#      (bpf/tinytap.bpf.c's read_iov) that #3's sendfile path never touches.
#   5. TLS: GET against a Python HTTPS server (self-signed cert, no Docker/
#      nginx needed) → the SSL_write/SSL_read uprobe pipeline (#146/#148)
#      must decrypt and pair the exchange exactly like a plaintext one. This
#      is deliberately not the nginx docker-compose scenario from #149's
#      issue text (this VM has no Docker) — it validates the same wiring
#      (sslWatcher → captureTLS → tls.FromSSL → Parser/Pairer) end-to-end
#      against a real TLS handshake instead.
#
# Usage: bash scripts/test-e2e.sh
# Exit code 0 = all assertions passed; non-zero = failure.

set -euo pipefail

PORT="${PORT:-18080}"
SLOW_PORT="${SLOW_PORT:-18081}"
FILE_PORT="${FILE_PORT:-18082}"
WRITEV_PORT="${WRITEV_PORT:-18083}"
TLS_PORT="${TLS_PORT:-18084}"
URL="http://localhost:${PORT}/"
# setcap'd file capabilities are silently dropped at exec on a nosuid mount
# (e.g. /tmp is nosuid on this dev VM) — TT_BIN must live somewhere else, so
# it's built into the repo root instead (gitignored, like the plain `tinytap`
# build artifact).
TT_BIN="${PWD}/tinytap-e2e"
TT_OUT=/tmp/tinytap-e2e.log
PY_LOG=/tmp/tinytap-e2e-py.log
SLOW_LOG=/tmp/tinytap-e2e-slow.log
FILE_LOG=/tmp/tinytap-e2e-file.log
WRITEV_LOG=/tmp/tinytap-e2e-writev.log
TLS_LOG=/tmp/tinytap-e2e-tls.log
TLS_CERT_DIR=/tmp/tinytap-e2e-tls-certs

PY_PID=""
SLOW_PY_PID=""
SLOW_CURL_PID=""
FILE_PID=""
WRITEV_PID=""
TLS_PY_PID=""
FAILURES=0

cleanup() {
    pkill -INT -x tinytap-e2e 2>/dev/null || true
    rm -f "${TT_BIN}"
    if [[ -n "${PY_PID}" ]]; then
        kill "${PY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${SLOW_PY_PID}" ]]; then
        kill -9 "${SLOW_PY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${SLOW_CURL_PID}" ]]; then
        kill "${SLOW_CURL_PID}" 2>/dev/null || true
    fi
    if [[ -n "${FILE_PID}" ]]; then
        kill "${FILE_PID}" 2>/dev/null || true
    fi
    if [[ -n "${WRITEV_PID}" ]]; then
        kill "${WRITEV_PID}" 2>/dev/null || true
    fi
    if [[ -n "${TLS_PY_PID}" ]]; then
        kill "${TLS_PY_PID}" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}
# check_no_leftover_processes (defined below) also runs on every EXIT path —
# not just the explicit end-of-script call — so an early failure (e.g. a
# server never starting listening) still gets verified, not just the happy
# path. The explicit end-of-script "cleanup; trap - EXIT; check_no_leftover_processes"
# sequence disables this trap first so the two don't run twice there.
trap 'cleanup; check_no_leftover_processes' EXIT

wait_for_port() {
    local host=$1 port=$2
    for _ in $(seq 1 50); do
        if (exec 3<>/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
            exec 3<&- 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_tinytap() {
    for _ in $(seq 1 50); do
        if grep -q "tinytap running" "${TT_OUT}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# wait_for_tls_attach waits for sslWatcher to finish its background
# discovery+attach for pid (a /proc scan + ELF symbol check, off the capture
# loop — see tlswatch.go). Until the "uprobes attached" line appears, any
# SSL_write/SSL_read the pid does happens before the uprobe is watching and
# won't be captured — so the TLS scenario must wait here before firing the
# request it actually asserts on, not just wait for the port to accept TCP
# connections. 30s (vs. 5s for wait_for_tinytap) because this involves two
# uprobe attaches plus a /proc+ELF scan, and CI runners are measurably
# slower than a dedicated dev VM for this path.
wait_for_tls_attach() {
    local pid=$1
    for _ in $(seq 1 300); do
        if grep -q "SSL_write/SSL_read/SSL_free uprobes attached for pid ${pid}" "${TT_OUT}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "  (tinytap output so far:)"
    cat "${TT_OUT}" 2>/dev/null || true
    return 1
}

assert_contains() {
    local description="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${TT_OUT}"; then
        echo "  PASS: ${description}"
    else
        echo "  FAIL: ${description} (pattern: ${pattern})"
        FAILURES=$((FAILURES + 1))
    fi
}

assert_absent() {
    local description="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${TT_OUT}"; then
        echo "  FAIL: ${description} (unexpected match for pattern: ${pattern})"
        FAILURES=$((FAILURES + 1))
    else
        echo "  PASS: ${description}"
    fi
}

# check_no_leftover_processes (#154) verifies cleanup() actually stopped
# everything it targeted. cleanup() swallows every kill/pkill failure with
# `|| true` (it must — a process that already exited is not an error), so
# without this, a signal that got ignored or a hung shutdown would pass
# silently. cleanup()'s own `wait` already blocks until every backgrounded
# job of this shell has exited, so a leftover found here means something
# escaped job control entirely (e.g. double-forked) rather than a timing
# race — treat it as a hard failure, not a retry-and-hope case.
check_no_leftover_processes() {
    local leftover=0

    # tinytap-e2e has no tracked PID here — matched by name instead, the
    # same way cleanup()'s `pkill -INT -x tinytap-e2e` targets it.
    if pgrep -x tinytap-e2e >/dev/null 2>&1; then
        echo "FAIL: tinytap-e2e still running after cleanup"
        pgrep -a -x tinytap-e2e || true
        leftover=1
    fi

    local pid_var
    for pid_var in PY_PID SLOW_PY_PID SLOW_CURL_PID FILE_PID WRITEV_PID TLS_PY_PID; do
        local pid="${!pid_var}"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            echo "FAIL: ${pid_var}=${pid} still running after cleanup"
            leftover=1
        fi
    done

    if [[ "${leftover}" -ne 0 ]]; then
        echo "FAIL: leftover process(es) after cleanup — see above"
        exit 1
    fi
}

echo "==> building tinytap"
go build -o "${TT_BIN}" ./cmd/tinytap/

echo "==> setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog on tinytap-e2e (see docs/capabilities.md — cap_sys_admin is for the TLS uprobe scenario, cap_syslog is for x86_64's live kallsyms lookup in the sendfile payload-capture kprobe)"
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip "${TT_BIN}"

# ── Scenario 2 setup: slow server (never responds) ───────────────────────────
# A Python server that accepts a connection but never sends a response,
# simulating a hung backend. We kill it with SIGKILL so the OS-level close
# triggers the SyscallClose path in tinytap.
echo "==> slow server on ${SLOW_PORT}"
python3 - "${SLOW_PORT}" >"${SLOW_LOG}" 2>&1 <<'PYEOF' &
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', port))
s.listen(1)
conn, _ = s.accept()
# Absorb the request bytes so curl sends its full payload, then hang forever.
conn.recv(4096)
time.sleep(9999)
PYEOF
SLOW_PY_PID=$!
wait_for_port localhost "${SLOW_PORT}" || { echo "FAIL: slow server did not listen on ${SLOW_PORT}"; exit 1; }

# ── Scenario 1 setup: normal http.server ─────────────────────────────────────
echo "==> python3 -m http.server ${PORT}"
python3 -m http.server "${PORT}" >"${PY_LOG}" 2>&1 &
PY_PID=$!
wait_for_port localhost "${PORT}" || { echo "FAIL: http.server did not listen on ${PORT}"; exit 1; }
kill -0 "${PY_PID}" 2>/dev/null || { echo "FAIL: http.server exited immediately (port ${PORT} already in use?)"; exit 1; }

# ── Scenario 3 setup: static file server (exercises the sendfile path) ───────
# http.ServeFile hands response bodies to the kernel via sendfile(2) once
# they're big enough (see docs/server-compat.md, Go net/http row). This
# exists to exercise the sendfile payload-capture kprobe in
# internal/loader/load.go: the fentry/tcp_sendmsg_locked kprobe that samples
# sendfile body bytes attaches on arm64 and amd64 (#112); on any other GOARCH
# tinytap logs a "skipping" line and captures byte counts only. The exchange
# must still pair successfully either way — Content-Length body framing never
# depends on payload bytes being sampled (see #116).
echo "==> Go static file server on ${FILE_PORT}"
cat > /tmp/tinytap-e2e-fileserver.go <<'GOEOF'
package main

import (
	"net/http"
	"os"
	"strings"
)

func main() {
	f, err := os.CreateTemp("", "tinytap-e2e-sendfile-*.bin")
	if err != nil {
		panic(err)
	}
	f.WriteString(strings.Repeat("F", 4096))
	f.Close()
	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, f.Name())
	})
	http.ListenAndServe(":"+os.Args[1], nil)
}
GOEOF
# Build ahead of starting it: `go run` compiles and execs in one step, and on
# a cold CI cache compiling net/http's dependency graph can take longer than
# wait_for_port's 5s budget, failing the wait before the server ever listens.
# A separate build step surfaces compile failures synchronously and keeps the
# wait loop bounded to actual startup time.
go build -o /tmp/tinytap-e2e-fileserver /tmp/tinytap-e2e-fileserver.go
/tmp/tinytap-e2e-fileserver "${FILE_PORT}" >"${FILE_LOG}" 2>&1 &
FILE_PID=$!
wait_for_port localhost "${FILE_PORT}" || { echo "FAIL: file server did not listen on ${FILE_PORT}"; exit 1; }

# ── Scenario 4 setup: writev server (exercises the multi-iovec path) ─────────
# Calls writev(2) directly with two iovecs — iovec[0] the response headers,
# iovec[1] the body — mirroring the cleanest real-world shape observed in
# docs/server-compat.md (Axum/hyper, #104). This exists to exercise #111's
# read_iov fix: without it, any body living outside iovec[0] is never
# sampled, regardless of size.
echo "==> Go writev server on ${WRITEV_PORT}"
cat > /tmp/tinytap-e2e-writevserver.go <<'GOEOF'
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	ln, err := net.Listen("tcp", ":"+os.Args[1])
	if err != nil {
		panic(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.Read(buf) // drain the request

	// Use SyscallConn to run writev(2) directly on the connection's own fd.
	// tc.File() would dup the fd instead — tinytap correlates a response
	// with its request by the accepting fd, so writing on a dup'd fd
	// orphans the response from the exchange and it shows as ABANDONED.
	tc := conn.(*net.TCPConn)
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}

	body := []byte("Hello, writev!")
	headers := []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(body)))

	var iov [2]syscall.Iovec
	iov[0].Base = &headers[0]
	iov[0].SetLen(len(headers))
	iov[1].Base = &body[0]
	iov[1].SetLen(len(body))

	var errno syscall.Errno
	writeErr := rc.Write(func(fd uintptr) bool {
		_, _, errno = syscall.Syscall(syscall.SYS_WRITEV, fd, uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
		// EINTR/EAGAIN/EWOULDBLOCK: not done yet — returning false makes
		// RawConn.Write wait for writability (or just retry) and call us
		// again, instead of treating a transient condition as a hard error.
		return errno != syscall.EINTR && errno != syscall.EAGAIN && errno != syscall.EWOULDBLOCK
	})
	if writeErr != nil || errno != 0 {
		fmt.Fprintln(os.Stderr, "writev failed:", writeErr, errno)
	}
}
GOEOF
go build -o /tmp/tinytap-e2e-writevserver /tmp/tinytap-e2e-writevserver.go
/tmp/tinytap-e2e-writevserver "${WRITEV_PORT}" >"${WRITEV_LOG}" 2>&1 &
WRITEV_PID=$!
wait_for_port localhost "${WRITEV_PORT}" || { echo "FAIL: writev server did not listen on ${WRITEV_PORT}"; exit 1; }

# ── Scenario 5 setup: Python HTTPS server (SSL_write/SSL_read/SSL_free uprobe
# pipeline, #149) ─────────────────────────────────────────────────────────────
# A self-signed cert + Python's ssl-wrapped http.server is enough to exercise
# the real uprobe pipeline end-to-end without Docker/nginx: Python's ssl
# module calls SSL_set_fd for its synchronous socket path (see #167), so this
# lands on the fd-resolvable path captureTLS supports today.
echo "==> TLS: generating self-signed cert"
mkdir -p "${TLS_CERT_DIR}"
openssl req -x509 -newkey rsa:2048 -keyout "${TLS_CERT_DIR}/key.pem" -out "${TLS_CERT_DIR}/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

echo "==> Python HTTPS server on ${TLS_PORT}"
cat > /tmp/tinytap-e2e-tlsserver.py <<PYEOF
import http.server, ssl

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"tls":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep TLS_LOG quiet; failures still surface via curl's exit code

httpd = http.server.HTTPServer(("127.0.0.1", ${TLS_PORT}), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("${TLS_CERT_DIR}/cert.pem", "${TLS_CERT_DIR}/key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PYEOF
python3 /tmp/tinytap-e2e-tlsserver.py >"${TLS_LOG}" 2>&1 &
TLS_PY_PID=$!
wait_for_port localhost "${TLS_PORT}" || { echo "FAIL: TLS server did not listen on ${TLS_PORT}"; exit 1; }

# AttachSSLSetFd/AttachSSLReadWrite deliberately never chmod their target
# themselves (a capture tool silently mutating a system library's
# permissions would be a surprising side effect — see load_uprobe.go's
# ErrLibSSLNotExecutable doc). Debian/Ubuntu ships libssl3 without the
# execute bit (mode 0644), unlike libc.so.6, so this e2e harness — which is
# already responsible for the rest of the test environment's setup — sets
# it explicitly instead of silently failing every SSL_set_fd/SSL_write/
# SSL_read/SSL_free attach for the rest of this run.
LIBSSL_PATH="$(ldconfig -p | grep 'libssl\.so\.3' | awk '{print $NF}' | head -1)"
if [[ -n "${LIBSSL_PATH}" && ! -x "${LIBSSL_PATH}" ]]; then
    echo "==> chmod +x ${LIBSSL_PATH} (Debian/Ubuntu ships libssl3 without the execute bit)"
    sudo chmod +x "${LIBSSL_PATH}"
fi

# ── Start tinytap (unprivileged — see the setcap call above) ─────────────────
echo "==> ${TT_BIN} --output stdout"
: >"${TT_OUT}"
"${TT_BIN}" --output stdout >"${TT_OUT}" 2>&1 &
wait_for_tinytap || { echo "FAIL: tinytap did not become ready"; exit 1; }

# ── Scenario 1: normal requests ───────────────────────────────────────────────
echo "==> firing normal requests"
curl -fsS --retry 3 --retry-delay 0 "${URL}" >/dev/null
curl -fsS --retry 3 --retry-delay 0 -I "${URL}" >/dev/null
post_exit=0
curl -fsS -X POST "${URL}" -d "hello" >/dev/null || post_exit=$?
[[ ${post_exit} -eq 0 || ${post_exit} -eq 22 ]] || exit "${post_exit}"

# ── Scenario 3: sendfile (static file) ────────────────────────────────────────
echo "==> firing sendfile request"
curl -fsS --retry 3 --retry-delay 0 "http://localhost:${FILE_PORT}/file" >/dev/null

# ── Scenario 4: writev (multi-iovec) ──────────────────────────────────────────
echo "==> firing writev request"
curl -fsS --retry 3 --retry-delay 0 "http://localhost:${WRITEV_PORT}/" >/dev/null

# ── Scenario 5: TLS ────────────────────────────────────────────────────────────
# The warm-up request triggers sslWatcher's pid discovery (it fires off the
# first observed event for this pid, same as every other scenario's server);
# the uprobe isn't attached yet when THIS request's SSL_write/SSL_read
# happen, so only the second request is expected to show up in TT_OUT.
echo "==> firing TLS warm-up request (triggers SSL uprobe discovery+attach)"
curl -fsSk --retry 3 --retry-delay 0 "https://localhost:${TLS_PORT}/" >/dev/null

wait_for_tls_attach "${TLS_PY_PID}" || { echo "FAIL: TLS uprobes did not attach for pid ${TLS_PY_PID}"; exit 1; }

echo "==> firing TLS request"
curl -fsSk --retry 3 --retry-delay 0 "https://localhost:${TLS_PORT}/" >/dev/null

# ── Scenario 2: abandoned request via kill -9 ────────────────────────────────
echo "==> firing request to slow server"
curl -fsS "http://localhost:${SLOW_PORT}/" >/dev/null &
SLOW_CURL_PID=$!
sleep 0.3  # give curl time to send its request headers

echo "==> kill -9 slow server (triggers OS-level close)"
kill -9 "${SLOW_PY_PID}" 2>/dev/null || true
SLOW_PY_PID=""
wait "${SLOW_CURL_PID}" 2>/dev/null || true
SLOW_CURL_PID=""

sleep 1

cleanup
trap - EXIT
check_no_leftover_processes

echo
echo "=== assertions ==="
assert_contains "GET / paired with 200"   "\[${PY_PID}\].*GET[[:space:]]+/[[:space:]].*200"
assert_contains "HEAD / paired with 200"  "\[${PY_PID}\].*HEAD[[:space:]]+/[[:space:]].*200"
assert_contains "POST / captured"         "\[${PY_PID}\].*POST[[:space:]]+/"
assert_contains "abandoned: peer closed"  "ABANDONED.*peer closed"
assert_contains "sendfile: GET /file paired with 200" "\[${FILE_PID}\].*GET[[:space:]]+/file[[:space:]].*200"
assert_contains "writev: GET / paired with 200" "\[${WRITEV_PID}\].*GET[[:space:]]+/[[:space:]].*200"
assert_contains "TLS: GET / paired with 200 (decrypted via SSL uprobe)" "\[${TLS_PY_PID}\].*GET[[:space:]]+/[[:space:]].*200"

# The sendfile payload-capture kprobe (#68) attaches on arm64 and amd64 (#112);
# on any other GOARCH, internal/loader/load.go logs a "skipping" line instead of
# attaching it. Assert whichever behavior matches the architecture this run is
# actually on, so the test passes both in the Lima VM (arm64) and in CI (x86_64)
# without hardcoding either.
ARCH="$(go env GOARCH)"
case "${ARCH}" in
arm64 | amd64)
    # A successful kprobe attach is silent (see tryAttachKprobe in
    # internal/loader/load.go) — every log line it emits means some step
    # failed. Assert none of them fired, i.e. the kprobe attached cleanly.
    assert_absent "sendfile payload capture kprobe attached without error (${ARCH})" \
        "sendfile payload capture (is arm64|disabled)"
    ;;
*)
    assert_contains "sendfile payload capture unsupported-arch guard logged (${ARCH})" \
        "kprobe sendfile payload capture is arm64/amd64-only, skipping on ${ARCH}"
    ;;
esac

echo
if [[ "${FAILURES}" -eq 0 ]]; then
    echo "PASS (all assertions)"
    exit 0
else
    echo "FAIL (${FAILURES} assertion(s) failed)"
    echo
    echo "=== captured output ==="
    cat "${TT_OUT}"
    exit 1
fi
