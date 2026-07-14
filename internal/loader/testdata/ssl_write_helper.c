// Minimal helper for internal/loader's uprobe_integration_test.go (#146).
//
// dlopen's the libssl path given as argv[1], creates a real (never
// handshaked) SSL object, reports its pointer, waits for a go-ahead on
// stdin, then calls the real SSL_write with a known plaintext buffer.
// SSL_write checks for a set write BIO before touching the network and
// returns an error immediately when none is set — but that check happens
// *inside* SSL_write, after the uprobe (attached at entry) has already
// captured the (ssl, buf, num) arguments, so no handshake or connected
// socket is needed to exercise the capture path. No <openssl/ssl.h> is
// needed — SSL/SSL_CTX/SSL_METHOD are treated as opaque pointers
// throughout, exactly as the uprobe program itself treats them.
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <libssl path>\n", argv[0]);
        return 1;
    }

    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    void *(*TLS_client_method)(void) = dlsym(h, "TLS_client_method");
    void *(*SSL_CTX_new)(const void *) = dlsym(h, "SSL_CTX_new");
    void *(*SSL_new)(void *) = dlsym(h, "SSL_new");
    int (*SSL_write)(void *, const void *, int) = dlsym(h, "SSL_write");
    if (!TLS_client_method || !SSL_CTX_new || !SSL_new || !SSL_write) {
        fprintf(stderr, "dlsym: missing required symbol\n");
        return 2;
    }

    void *ctx = SSL_CTX_new(TLS_client_method());
    void *ssl = SSL_new(ctx);
    if (!ctx || !ssl) {
        fprintf(stderr, "setup failed: ctx=%p ssl=%p\n", ctx, ssl);
        return 3;
    }

    printf("READY %p\n", ssl);
    fflush(stdout);

    char buf[8];
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        fprintf(stderr, "stdin closed before go-ahead\n");
        return 4;
    }

    static const char plaintext[] = "hello-tinytap-146";
    SSL_write(ssl, plaintext, (int)(sizeof(plaintext) - 1)); // return value deliberately ignored, see file comment
    printf("DONE\n");
    fflush(stdout);
    return 0;
}
