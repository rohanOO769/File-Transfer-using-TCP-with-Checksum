// client_tcp.c

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
#include <errno.h>
#include <time.h>

#define TCP_PORT 5001

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

// Send message with 4-byte length prefix.
int send_msg(int sock, const unsigned char *data, uint32_t len) {
    uint32_t net_len = htonl(len);
    if(send_all(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
        return -1;
    if(send_all(sock, data, len) != len)
        return -1;
    return 0;
}

// Receive message with 4-byte length prefix; allocates buffer (caller frees).
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
    unsigned char *data;
    uint32_t data_len;
} ChunkData;

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        exit(1);
    }
    const char *file_path = argv[1];

    // Read file.
    FILE *fp = fopen(file_path, "rb");
    if(!fp) { perror("fopen"); exit(1); }
    fseek(fp, 0, SEEK_END);
    uint32_t file_len = ftell(fp);
    rewind(fp);
    unsigned char *file_data = malloc(file_len);
    if(fread(file_data, 1, file_len, fp) != file_len) {
        perror("fread");
        exit(1);
    }
    fclose(fp);
    printf("Client: read file of %u bytes.\n", file_len);

    // Connect to server.
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) { perror("socket"); exit(1); }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TCP_PORT);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        exit(1);
    }
    printf("Client: connected to server.\n");

    // Send file with length prefix.
    if(send_msg(sockfd, file_data, file_len) < 0) {
        perror("send_msg file");
        exit(1);
    }
    printf("Client: sent file data (%u bytes).\n", file_len);

    // Receive header: 4 bytes (total_chunks) + 64 bytes (overall checksum in hex).
    unsigned char *header = NULL;
    uint32_t header_len;
    if(recv_msg(sockfd, &header, &header_len) < 0) {
        perror("recv_msg header");
        exit(1);
    }
    if(header_len != (4+64)) {
        fprintf(stderr, "Client: unexpected header length: %u\n", header_len);
        exit(1);
    }
    uint32_t total_chunks;
    memcpy(&total_chunks, header, 4);
    total_chunks = ntohl(total_chunks);
    char expected_checksum[65];
    memcpy(expected_checksum, header+4, 64);
    expected_checksum[64] = '\0';
    printf("Client: expecting %u chunks, overall checksum: %s\n", total_chunks, expected_checksum);
    free(header);

    // Allocate array for chunks.
    ChunkData *chunks = calloc(total_chunks, sizeof(ChunkData));
    if(!chunks) { perror("calloc chunks"); exit(1); }
    uint32_t received_count = 0;
    while(received_count < total_chunks) {
        unsigned char *chunk_msg = NULL;
        uint32_t chunk_msg_len;
        if(recv_msg(sockfd, &chunk_msg, &chunk_msg_len) < 0) {
            perror("recv_msg chunk");
            break;
        }
        if(chunk_msg_len < 4 + SHA256_DIGEST_LENGTH) {
            free(chunk_msg);
            continue;
        }
        uint32_t seq;
        memcpy(&seq, chunk_msg, 4);
        seq = ntohl(seq);
        uint32_t data_len = chunk_msg_len - 4 - SHA256_DIGEST_LENGTH;
        unsigned char *chunk_data = chunk_msg + 4 + SHA256_DIGEST_LENGTH;
        unsigned char computed_hash[SHA256_DIGEST_LENGTH];
        SHA256(chunk_data, data_len, computed_hash);
        if(memcmp(computed_hash, chunk_msg+4, SHA256_DIGEST_LENGTH) != 0) {
            printf("Client: chunk %u corrupted.\n", seq);
            if(chunks[seq].data) {
                free(chunks[seq].data);
                chunks[seq].data = NULL;
                chunks[seq].data_len = 0;
                received_count--;
            }
        } else {
            if(chunks[seq].data == NULL) {
                chunks[seq].data = malloc(data_len);
                if(chunks[seq].data == NULL) { perror("malloc chunk"); exit(1); }
                memcpy(chunks[seq].data, chunk_data, data_len);
                chunks[seq].data_len = data_len;
                received_count++;
                printf("Client: received chunk %u.\n", seq);
            }
        }
        free(chunk_msg);
    }
    printf("Client: initial reception complete. Received %u/%u chunks.\n", received_count, total_chunks);

    // Retransmission loop (up to 5 rounds).
    int rounds = 0;
    while(received_count < total_chunks && rounds < 5) {
        uint32_t missing_count = total_chunks - received_count;
        uint32_t req_len = 3 + 4 + 4 * missing_count;
        unsigned char *req = malloc(req_len);
        memcpy(req, "REQ", 3);
        uint32_t net_missing = htonl(missing_count);
        memcpy(req+3, &net_missing, 4);
        int j = 0;
        for(uint32_t i = 0; i < total_chunks; i++) {
            if(chunks[i].data == NULL) {
                uint32_t net_seq = htonl(i);
                memcpy(req+3+4+j*4, &net_seq, 4);
                j++;
            }
        }
        if(send_msg(sockfd, req, req_len) < 0) {
            perror("send_msg retransmission req");
            free(req);
            break;
        }
        free(req);
        // Set a timeout for retransmitted chunks.
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        unsigned char *chunk_msg = NULL;
        uint32_t chunk_msg_len;
        while(recv_msg(sockfd, &chunk_msg, &chunk_msg_len) > 0) {
            if(chunk_msg_len < 4 + SHA256_DIGEST_LENGTH) {
                free(chunk_msg);
                continue;
            }
            uint32_t seq;
            memcpy(&seq, chunk_msg, 4);
            seq = ntohl(seq);
            uint32_t data_len = chunk_msg_len - 4 - SHA256_DIGEST_LENGTH;
            unsigned char *chunk_data = chunk_msg + 4 + SHA256_DIGEST_LENGTH;
            unsigned char computed_hash[SHA256_DIGEST_LENGTH];
            SHA256(chunk_data, data_len, computed_hash);
            if(memcmp(computed_hash, chunk_msg+4, SHA256_DIGEST_LENGTH) != 0) {
                printf("Client: retransmitted chunk %u corrupted.\n", seq);
                if(chunks[seq].data) {
                    free(chunks[seq].data);
                    chunks[seq].data = NULL;
                    chunks[seq].data_len = 0;
                    received_count--;
                }
            } else {
                if(chunks[seq].data == NULL) {
                    chunks[seq].data = malloc(data_len);
                    if(chunks[seq].data == NULL) { perror("malloc chunk"); exit(1); }
                    memcpy(chunks[seq].data, chunk_data, data_len);
                    chunks[seq].data_len = data_len;
                    received_count++;
                    printf("Client: received retransmitted chunk %u.\n", seq);
                }
            }
            free(chunk_msg);
        }
        rounds++;
    }

    if(received_count < total_chunks) {
        printf("Client: Failed to receive all chunks. Missing %u chunks.\n", total_chunks - received_count);
    } else {
        uint32_t total_data = 0;
        for(uint32_t i = 0; i < total_chunks; i++)
            total_data += chunks[i].data_len;
        unsigned char *reassembled = malloc(total_data);
        uint32_t offset = 0;
        for(uint32_t i = 0; i < total_chunks; i++) {
            memcpy(reassembled + offset, chunks[i].data, chunks[i].data_len);
            offset += chunks[i].data_len;
        }
        unsigned char final_hash[SHA256_DIGEST_LENGTH];
        SHA256(reassembled, total_data, final_hash);
        char final_hash_hex[65];
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            sprintf(&final_hash_hex[i*2], "%02x", final_hash[i]);
        final_hash_hex[64] = '\0';
        printf("Client: Reassembled file size: %u bytes. Checksum: %s\n", total_data, final_hash_hex);
        if(strcmp(final_hash_hex, expected_checksum) == 0)
            printf("Client: Transfer successful: Checksum verified!\n");
        else
            printf("Client: Transfer failed: Checksum mismatch!\n");
        free(reassembled);
    }

    // Send DONE message.
    if(send_msg(sockfd, (unsigned char*)"DONE", 4) < 0)
        perror("send_msg DONE");
    close(sockfd);
    for(uint32_t i = 0; i < total_chunks; i++) {
        if(chunks[i].data)
            free(chunks[i].data);
    }
    free(chunks);
    free(file_data);
    return 0;
}
