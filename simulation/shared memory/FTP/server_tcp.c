// server_tcp.c

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
#include <time.h>
#include <errno.h>

#define TCP_PORT 5001

// Choose chunk size based on file size: if file > 100MB, use 1MB chunks; otherwise, 1KB.
#define CHUNK_SIZE_SMALL 1024
#define CHUNK_SIZE_LARGE (1024*1024)

// Error simulation probabilities
double DROP_PROB = 0.2;     // 20% drop
double CORRUPT_PROB = 0.1;  // 10% corruption

// Helper: send all data
ssize_t send_all(int sock, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = buf;
    while (total < len) {
        ssize_t n = send(sock, p+total, len-total, 0);
        if(n <= 0) return n;
        total += n;
    }
    return total;
}

// Helper: receive all data
ssize_t recv_all(int sock, void *buf, size_t len) {
    size_t total = 0;
    char *p = buf;
    while (total < len) {
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

// Receive a message with a 4-byte length prefix; allocates buffer (caller must free).
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
    unsigned char *data; // pointer to chunk data
    uint32_t data_len;
} Chunk;

int main(void) {
    srand(time(NULL));

    // Set up TCP listening socket.
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) { perror("socket"); exit(1); }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(TCP_PORT);
    if(bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind"); exit(1);
    }
    if(listen(sockfd, 1) < 0) { perror("listen"); exit(1); }
    printf("TCP Server listening on port %d...\n", TCP_PORT);

    int conn = accept(sockfd, NULL, NULL);
    if(conn < 0) { perror("accept"); exit(1); }
    printf("TCP connection accepted.\n");

    // --- Receive entire file from client ---
    unsigned char *file_data = NULL;
    uint32_t file_len;
    if(recv_msg(conn, &file_data, &file_len) < 0) {
        perror("recv_msg file");
        close(conn);
        exit(1);
    }
    printf("Server: received file of %u bytes.\n", file_len);

    // --- Decide on chunk size and split file ---
    uint32_t chunk_size = (file_len > 100*1024*1024) ? CHUNK_SIZE_LARGE : CHUNK_SIZE_SMALL;
    uint32_t total_chunks = (file_len + chunk_size - 1) / chunk_size;
    printf("Server: splitting file into %u chunks of up to %u bytes.\n", total_chunks, chunk_size);

    // Compute overall file checksum.
    unsigned char overall_hash[SHA256_DIGEST_LENGTH];
    SHA256(file_data, file_len, overall_hash);
    char overall_hash_hex[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&overall_hash_hex[i*2], "%02x", overall_hash[i]);
    overall_hash_hex[64] = '\0';

    // Split into chunks.
    Chunk *chunks = malloc(total_chunks * sizeof(Chunk));
    if(!chunks) { perror("malloc chunks"); exit(1); }
    for(uint32_t i = 0; i < total_chunks; i++) {
        chunks[i].seq = i;
        uint32_t start = i * chunk_size;
        uint32_t this_chunk_size = (start + chunk_size <= file_len) ? chunk_size : (file_len - start);
        chunks[i].data_len = this_chunk_size;
        chunks[i].data = malloc(this_chunk_size);
        if(!chunks[i].data) { perror("malloc chunk data"); exit(1); }
        memcpy(chunks[i].data, file_data + start, this_chunk_size);
        SHA256(chunks[i].data, this_chunk_size, chunks[i].hash);
    }

    // --- Send header ---
    // Header: 4 bytes (total_chunks in network order) + 64 bytes (overall file checksum hex)
    uint32_t header_len = 4 + 64;
    unsigned char *header = malloc(header_len);
    uint32_t net_total = htonl(total_chunks);
    memcpy(header, &net_total, 4);
    memcpy(header+4, overall_hash_hex, 64);
    if(send_msg(conn, header, header_len) < 0) {
        perror("send_msg header");
        exit(1);
    }
    printf("Server: sent header with total_chunks=%u and checksum=%s\n", total_chunks, overall_hash_hex);
    free(header);

    // --- Shuffle chunk order ---
    uint32_t *indices = malloc(total_chunks * sizeof(uint32_t));
    for(uint32_t i = 0; i < total_chunks; i++)
        indices[i] = i;
    for(uint32_t i = 0; i < total_chunks; i++) {
        uint32_t j = i + rand() % (total_chunks - i);
        uint32_t temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    // --- Send all chunks in shuffled order ---
    for(uint32_t i = 0; i < total_chunks; i++) {
        uint32_t idx = indices[i];
        uint32_t msg_len = 4 + SHA256_DIGEST_LENGTH + chunks[idx].data_len;
        unsigned char *msg = malloc(msg_len);
        uint32_t net_seq = htonl(chunks[idx].seq);
        memcpy(msg, &net_seq, 4);
        memcpy(msg+4, chunks[idx].hash, SHA256_DIGEST_LENGTH);
        memcpy(msg+4+SHA256_DIGEST_LENGTH, chunks[idx].data, chunks[idx].data_len);

        // Apply error simulation.
        double r = (double)rand() / RAND_MAX;
        if(r < DROP_PROB) {
            printf("Server: Dropped chunk %u (simulated).\n", chunks[idx].seq);
            free(msg);
            continue;
        } else if(r < DROP_PROB + CORRUPT_PROB) {
            printf("Server: Corrupted chunk %u (simulated).\n", chunks[idx].seq);
            if(chunks[idx].data_len > 0) {
                msg[4 + SHA256_DIGEST_LENGTH] ^= 0xFF;
            }
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

    // --- Retransmission Loop ---
    int rounds = 0;
    while(rounds < 5) {
        // Set socket timeout.
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        unsigned char *req_msg = NULL;
        uint32_t req_len;
        if(recv_msg(conn, &req_msg, &req_len) < 0) {
            break; // timeout or error
        }
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

    // Cleanup: free chunks and file data.
    for(uint32_t i = 0; i < total_chunks; i++) {
        free(chunks[i].data);
    }
    free(chunks);
    free(file_data);
    close(conn);
    close(sockfd);
    printf("Server: connection closed.\n");
    return 0;
}
