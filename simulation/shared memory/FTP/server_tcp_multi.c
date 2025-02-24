// server_tcp_multi.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#define TCP_PORT 5001
// For files ≤ 100MB use 1KB chunks; otherwise, 1MB chunks.
#define CHUNK_SIZE_SMALL 1024
#define CHUNK_SIZE_LARGE (1024*1024)
// Error simulation probabilities (adjust as needed)
double DROP_PROB = 0.2;
double CORRUPT_PROB = 0.1;

// Helper function: send all bytes
ssize_t send_all(int sock, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = buf;
    while(total < len) {
        ssize_t n = send(sock, p+total, len-total, 0);
        if(n <= 0) return n;
        total += n;
    }
    return total;
}

// Helper function: receive all bytes
ssize_t recv_all(int sock, void *buf, size_t len) {
    size_t total = 0;
    char *p = buf;
    while(total < len) {
        ssize_t n = recv(sock, p+total, len-total, 0);
        if(n <= 0) return n;
        total += n;
    }
    return total;
}

// Send a message with a 4-byte length prefix.
int send_msg(int sock, const unsigned char *data, uint32_t len) {
    uint32_t net_len = htonl(len);
    if(send_all(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
        return -1;
    if(send_all(sock, data, len) != len)
        return -1;
    return 0;
}

// Receive a message with a 4-byte length prefix; allocate buffer (caller must free).
int recv_msg(int sock, unsigned char **data, uint32_t *len) {
    uint32_t net_len;
    if(recv_all(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
        return -1;
    *len = ntohl(net_len);
    *data = malloc(*len);
    if(*data == NULL) return -1;
    if(recv_all(sock, *data, *len) != *len) {
        free(*data);
        return -1;
    }
    return 0;
}

typedef struct {
    uint32_t seq;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char *data;  // Pointer to chunk data
    uint32_t data_len;
} Chunk;

//
// handle_client: processes one client connection
//
void *handle_client(void *arg) {
    int conn = *(int *)arg;
    free(arg);

    // --- Receive the entire file from the client ---
    unsigned char *file_data = NULL;
    uint32_t file_len;
    if(recv_msg(conn, &file_data, &file_len) < 0) {
        perror("recv_msg file");
        close(conn);
        pthread_exit(NULL);
    }
    printf("Server: received file of %u bytes.\n", file_len);

    // --- Determine chunk size and split file ---
    uint32_t chunk_size = (file_len > 100*1024*1024) ? CHUNK_SIZE_LARGE : CHUNK_SIZE_SMALL;
    uint32_t total_chunks = (file_len + chunk_size - 1) / chunk_size;
    printf("Server: splitting file into %u chunks (chunk size %u bytes).\n", total_chunks, chunk_size);

    // --- Compute overall file checksum ---
    unsigned char overall_hash[SHA256_DIGEST_LENGTH];
    SHA256(file_data, file_len, overall_hash);
    char overall_hash_hex[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&overall_hash_hex[i*2], "%02x", overall_hash[i]);
    overall_hash_hex[64] = '\0';

    // --- Send header: 4 bytes (total_chunks) + 64-byte checksum ---
    uint32_t header_len = 4 + 64;
    unsigned char *header = malloc(header_len);
    if(!header) { perror("malloc header"); close(conn); pthread_exit(NULL); }
    uint32_t net_total = htonl(total_chunks);
    memcpy(header, &net_total, 4);
    memcpy(header+4, overall_hash_hex, 64);
    if(send_msg(conn, header, header_len) < 0) {
        perror("send_msg header");
        free(header);
        close(conn);
        pthread_exit(NULL);
    }
    printf("Server: sent header with total_chunks=%u and checksum=%s\n", total_chunks, overall_hash_hex);
    free(header);

    // --- Split file into chunks ---
    Chunk *chunks = malloc(total_chunks * sizeof(Chunk));
    if(!chunks) { perror("malloc chunks"); close(conn); pthread_exit(NULL); }
    for(uint32_t i = 0; i < total_chunks; i++) {
        chunks[i].seq = i;
        uint32_t start = i * chunk_size;
        uint32_t this_chunk_size = (start + chunk_size <= file_len) ? chunk_size : (file_len - start);
        chunks[i].data_len = this_chunk_size;
        chunks[i].data = malloc(this_chunk_size);
        if(!chunks[i].data) { perror("malloc chunk data"); close(conn); pthread_exit(NULL); }
        memcpy(chunks[i].data, file_data + start, this_chunk_size);
        SHA256(chunks[i].data, this_chunk_size, chunks[i].hash);
    }
    free(file_data);

    // --- Shuffle chunk order ---
    uint32_t *indices = malloc(total_chunks * sizeof(uint32_t));
    if(!indices) { perror("malloc indices"); close(conn); pthread_exit(NULL); }
    for(uint32_t i = 0; i < total_chunks; i++)
        indices[i] = i;
    for(uint32_t i = 0; i < total_chunks; i++) {
        uint32_t j = i + rand() % (total_chunks - i);
        uint32_t temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    // --- Send chunks in shuffled order with error simulation ---
    for(uint32_t i = 0; i < total_chunks; i++) {
        uint32_t idx = indices[i];
        uint32_t msg_len = 4 + SHA256_DIGEST_LENGTH + chunks[idx].data_len;
        unsigned char *msg = malloc(msg_len);
        if(!msg) { perror("malloc msg"); continue; }
        uint32_t net_seq = htonl(chunks[idx].seq);
        memcpy(msg, &net_seq, 4);
        memcpy(msg+4, chunks[idx].hash, SHA256_DIGEST_LENGTH);
        memcpy(msg+4+SHA256_DIGEST_LENGTH, chunks[idx].data, chunks[idx].data_len);
        double r = (double)rand() / RAND_MAX;
        if(r < DROP_PROB) {
            printf("Server: Dropped chunk %u (simulated).\n", chunks[idx].seq);
            free(msg);
            continue;
        } else if(r < DROP_PROB + CORRUPT_PROB) {
            printf("Server: Corrupted chunk %u (simulated).\n", chunks[idx].seq);
            if(chunks[idx].data_len > 0)
                msg[4+SHA256_DIGEST_LENGTH] ^= 0xFF;
        }
        if(send_msg(conn, msg, msg_len) < 0) {
            perror("send_msg chunk");
            free(msg);
            break;
        }
        free(msg);
    }
    free(indices);
    printf("Server: initial transmission complete.\n");

    // --- Retransmission Loop (up to 5 rounds) ---
    int rounds = 0;
    while(rounds < 5) {
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        unsigned char *req_msg = NULL;
        uint32_t req_len;
        if(recv_msg(conn, &req_msg, &req_len) < 0) {
            break; // timeout or error
        }
        // If client sends "DONE", break out.
        if(req_len == 4 && memcmp(req_msg, "DONE", 4) == 0) {
            free(req_msg);
            printf("Server: Received DONE. Finishing.\n");
            break;
        }
        if(req_len < 7 || memcmp(req_msg, "REQ", 3) != 0) {
            free(req_msg);
            continue;
        }
        uint32_t missing_count;
        memcpy(&missing_count, req_msg+3, 4);
        missing_count = ntohl(missing_count);
        printf("Server: Retransmission request for %u chunks.\n", missing_count);
        for(uint32_t i = 0; i < missing_count; i++) {
            if(7 + 4*i + 4 > req_len) break;
            uint32_t seq;
            memcpy(&seq, req_msg+7 + i*4, 4);
            seq = ntohl(seq);
            if(seq < total_chunks) {
                uint32_t msg_len = 4 + SHA256_DIGEST_LENGTH + chunks[seq].data_len;
                unsigned char *msg = malloc(msg_len);
                if(!msg) continue;
                uint32_t net_seq = htonl(chunks[seq].seq);
                memcpy(msg, &net_seq, 4);
                memcpy(msg+4, chunks[seq].hash, SHA256_DIGEST_LENGTH);
                memcpy(msg+4+SHA256_DIGEST_LENGTH, chunks[seq].data, chunks[seq].data_len);
                if(send_msg(conn, msg, msg_len) < 0) {
                    perror("send_msg retransmit");
                    free(msg);
                    break;
                }
                printf("Server: Resent chunk %u.\n", seq);
                free(msg);
            }
        }
        free(req_msg);
        rounds++;
    }

    // Cleanup allocated memory for chunks.
    for(uint32_t i = 0; i < total_chunks; i++) {
        free(chunks[i].data);
    }
    free(chunks);
    close(conn);
    printf("Server: connection closed.\n");
    pthread_exit(NULL);
}

int main(void) {
    srand(time(NULL));
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) { perror("socket"); exit(1); }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(TCP_PORT);
    if(bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        exit(1);
    }
    if(listen(sockfd, 10) < 0) {
        perror("listen");
        exit(1);
    }
    printf("TCP Server listening on port %d...\n", TCP_PORT);

    while(1) {
        int *conn = malloc(sizeof(int));
        if((*conn = accept(sockfd, NULL, NULL)) < 0) {
            perror("accept");
            free(conn);
            continue;
        }
        printf("TCP connection accepted.\n");
        pthread_t tid;
        if(pthread_create(&tid, NULL, handle_client, conn) != 0) {
            perror("pthread_create");
            close(*conn);
            free(conn);
            continue;
        }
        pthread_detach(tid);
    }
    close(sockfd);
    return 0;
}
