#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>

#define PORT 4443
#define BUFFER 4096

int total_requests = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// ===== CHECKSUM =====
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// ===== DNS =====
char* resolve_domain(char *host) {
    static char ip[INET_ADDRSTRLEN];
    struct hostent *he = gethostbyname(host);
    if (!he) return NULL;
    strcpy(ip, inet_ntoa(*(struct in_addr*)he->h_addr));
    return ip;
}

// ===== RAW PING =====
void raw_ping(char *ip, SSL *ssl) {

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct timeval timeout = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);

    int sent = 0, received = 0;
    double total_rtt = 0, min_rtt = 999999, max_rtt = 0;

    for (int i = 0; i < 4; i++) {

        char packet[64] = {0};
        struct icmp *icmp = (struct icmp*)packet;

        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_seq = i;
        icmp->icmp_cksum = checksum(packet, sizeof(packet));

        struct timeval start, end;
        gettimeofday(&start, NULL);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr*)&addr, sizeof(addr));

        sent++;

        char recvbuf[1024];
        socklen_t len = sizeof(addr);

        int n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr*)&addr, &len);

        if (n > 0) {

            gettimeofday(&end, NULL);

            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                         (end.tv_usec - start.tv_usec) / 1000.0;

            total_rtt += rtt;
            if (rtt < min_rtt) min_rtt = rtt;
            if (rtt > max_rtt) max_rtt = rtt;

            char output[256];
            snprintf(output, sizeof(output),
                     "64 bytes from %s: time=%.2f ms\n", ip, rtt);

            SSL_write(ssl, output, strlen(output));
            received++;
        }

        sleep(1);
    }

    double avg = received ? total_rtt / received : 0;

    char stats[512];
    snprintf(stats, sizeof(stats),
        "\nPackets Sent: %d\n"
        "Packets Received: %d\n"
        "Packet Loss: %.2f %%\n"
        "RTT Avg: %.2f ms | Min: %.2f ms | Max: %.2f ms\n",
        sent, received,
        ((sent - received) / (double)sent) * 100,
        avg, min_rtt, max_rtt);

    SSL_write(ssl, stats, strlen(stats));

    close(sock);
}

// ===== TRACEROUTE =====
void raw_traceroute(char *ip, SSL *ssl) {

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct timeval timeout = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);

    for (int ttl = 1; ttl <= 10; ttl++) {

        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        char packet[64] = {0};
        struct icmp *icmp = (struct icmp*)packet;

        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_seq = ttl;
        icmp->icmp_cksum = checksum(packet, sizeof(packet));

        struct timeval start, end;
        gettimeofday(&start, NULL);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr*)&addr, sizeof(addr));

        char recvbuf[1024];
        socklen_t len = sizeof(addr);

        int n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr*)&addr, &len);

        gettimeofday(&end, NULL);

        double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                     (end.tv_usec - start.tv_usec) / 1000.0;

        char output[256];

        if (n > 0)
            snprintf(output, sizeof(output), "%d  %s  %.2f ms\n",
                     ttl, inet_ntoa(addr.sin_addr), rtt);
        else
            snprintf(output, sizeof(output), "%d  * * *\n", ttl);

        SSL_write(ssl, output, strlen(output));
    }

    close(sock);
}

// ===== CLIENT HANDLER =====
void *handle_client(void *arg) {

    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER];

    struct timeval start, end;
    gettimeofday(&start, NULL);

    pthread_mutex_lock(&lock);
    total_requests++;
    pthread_mutex_unlock(&lock);

    int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (bytes <= 0) {
        SSL_free(ssl);
        pthread_exit(NULL);
    }

    buffer[bytes] = '\0';
    buffer[strcspn(buffer, "\n")] = 0;

    printf("Client request: %s\n", buffer);
    fflush(stdout);

    int multi = 0;

    if (strncmp(buffer, "PING ", 5) == 0) {

        char *token = strtok(buffer + 5, " ");

        while (token) {
            multi++;
            printf("Pinged: %s\n", token);
            fflush(stdout);

            char *ip = resolve_domain(token);
            if (!ip) ip = "127.0.0.1";

            raw_ping(ip, ssl);
            token = strtok(NULL, " ");
        }
    }

    else if (strncmp(buffer, "TRACEROUTE ", 11) == 0) {

        char *token = strtok(buffer + 11, " ");

        while (token) {
            multi++;
            printf("Traceroute: %s\n", token);
            fflush(stdout);

            char *ip = resolve_domain(token);
            if (!ip) ip = "127.0.0.1";

            raw_traceroute(ip, ssl);
            token = strtok(NULL, " ");
        }
    }

    gettimeofday(&end, NULL);

    double response_time = (end.tv_sec - start.tv_sec) * 1000.0 +
                           (end.tv_usec - start.tv_usec) / 1000.0;

    double throughput = total_requests / (response_time / 1000.0);

    char perf[512];
    snprintf(perf, sizeof(perf),
        "\n=== PERFORMANCE METRICS ===\n"
        "Response Time: %.2f ms\n"
        "Throughput: %.2f req/sec\n"
        "Total Requests: %d\n"
        "Multi-Destination: %d\n"
        "===========================\n",
        response_time, throughput, total_requests, multi);

    SSL_write(ssl, perf, strlen(perf));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_exit(NULL);
}
