// Minimal helper for internal/loader's uprobe_integration_test.go (#147).
//
// dlopen's the libssl path given as argv[1], creates a real (never
// handshaked) SSL object and a real socket fd, reports both, waits for a
// go-ahead on stdin, then calls the real SSL_set_fd. No <openssl/ssl.h> is
// needed — SSL/SSL_CTX/SSL_METHOD are treated as opaque pointers throughout,
// exactly as the uprobe program itself treats them.
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>

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
    int (*SSL_set_fd)(void *, int) = dlsym(h, "SSL_set_fd");
    if (!TLS_client_method || !SSL_CTX_new || !SSL_new || !SSL_set_fd) {
        fprintf(stderr, "dlsym: missing required symbol\n");
        return 2;
    }

    void *ctx = SSL_CTX_new(TLS_client_method());
    void *ssl = SSL_new(ctx);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!ctx || !ssl || fd < 0) {
        fprintf(stderr, "setup failed: ctx=%p ssl=%p fd=%d\n", ctx, ssl, fd);
        return 3;
    }

    printf("READY %p %d\n", ssl, fd);
    fflush(stdout);

    char buf[8];
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        fprintf(stderr, "stdin closed before go-ahead\n");
        return 4;
    }

    SSL_set_fd(ssl, fd);
    printf("DONE\n");
    fflush(stdout);
    return 0;
}
