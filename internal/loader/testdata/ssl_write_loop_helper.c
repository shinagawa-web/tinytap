// Helper for internal/loader's ssl_ringbuf_drops_integration_test.go
// (#290). Same setup as ssl_write_helper.c (one dlopen'd, never-handshaked
// SSL object), but calls SSL_write argv[2] times after the go-ahead
// instead of once, to force the ssl_events ringbuf (1 MiB, the smallest
// ring tinytap runs) to overflow with nothing draining it.
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <libssl path> <count>\n", argv[0]);
        return 1;
    }
    long count = strtol(argv[2], NULL, 10);

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

    static const char plaintext[] = "hello-tinytap-290";
    for (long i = 0; i < count; i++) {
        SSL_write(ssl, plaintext, (int)(sizeof(plaintext) - 1)); // return value deliberately ignored, see ssl_write_helper.c
    }
    printf("DONE\n");
    fflush(stdout);
    return 0;
}
