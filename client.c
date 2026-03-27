#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>

#define PORT 4443
#define BUFFER 4096

int main() {

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr("10.5.25.181"); // CHANGE

    connect(sock, (struct sockaddr*)&server, sizeof(server));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    SSL_connect(ssl);

    printf("Connected to server\n");

    char command[256];

    printf("Enter command: ");
    fgets(command, sizeof(command), stdin);
    command[strcspn(command, "\n")] = 0;

    struct timeval start, end;
    gettimeofday(&start, NULL);

    SSL_write(ssl, command, strlen(command));

    char buffer[BUFFER];
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer)-1)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);
    }

    gettimeofday(&end, NULL);

    double latency = (end.tv_sec - start.tv_sec) * 1000.0 +
                     (end.tv_usec - start.tv_usec) / 1000.0;

    printf("\n[CLIENT LATENCY]: %.2f ms\n", latency);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}client code
