#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4443
#define BUFFER 4096

void *handle_client(void *arg) {

    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER];

    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }

    buffer[bytes] = '\0';

    // remove newline
    buffer[strcspn(buffer, "\n")] = 0;

    printf("Received command: %s\n", buffer);

    if (strncmp(buffer, "PING ", 5) == 0) {

        char command[256];
        snprintf(command, sizeof(command), "ping -c 2 %s", buffer + 5);

        FILE *fp = popen(command, "r");

        char output[BUFFER];
        while (fgets(output, sizeof(output), fp)) {
            SSL_write(ssl, output, strlen(output));
        }

        pclose(fp);
    }

    else if (strncmp(buffer, "TRACEROUTE ", 11) == 0) {

        char command[256];
        snprintf(command, sizeof(command), "traceroute %s", buffer + 11);

        FILE *fp = popen(command, "r");

        char output[BUFFER];
        while (fgets(output, sizeof(output), fp)) {
            SSL_write(ssl, output, strlen(output));
        }

        pclose(fp);
    }

    else {

        char *msg = "Invalid command\n";
        SSL_write(ssl, msg, strlen(msg));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    pthread_exit(NULL);
}

int main() {

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) {
        printf("SSL context failed\n");
        return 1;
    }

    if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {

        printf("Certificate error\n");
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    printf("Secure Server running on port %d...\n", PORT);

    while (1) {

        struct sockaddr_in client;
        socklen_t len = sizeof(client);

        int client_fd = accept(server_fd, (struct sockaddr*)&client, &len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {

            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, ssl);
        pthread_detach(tid);
    }

    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}
