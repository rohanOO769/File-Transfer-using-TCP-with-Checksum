// encryption/client/client_tcp_enc.c 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define TCP_PORT 5001

// --- Basic send/recv helpers with length prefix ---

ssize_t send_all(int sock, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = buf;
    while(total < len) {
        ssize_t n = send(sock, p + total, len - total, 0);
        if(n <= 0)
            return n;
        total += n;
    }
    return total;
}

ssize_t recv_all(int sock, void *buf, size_t len) {
    size_t total = 0;
    char *p = buf;
    while(total < len) {
        ssize_t n = recv(sock, p + total, len - total, 0);
        if(n <= 0)
            return n;
        total += n;
    }
    return total;
}

int send_msg(int sock, const unsigned char *data, uint32_t len) {
    uint32_t net_len = htonl(len);
    if(send_all(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
        return -1;
    if(send_all(sock, data, len) != len)
        return -1;
    return 0;
}

int recv_msg(int sock, unsigned char **data, uint32_t *len) {
    uint32_t net_len;
    if(recv_all(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
        return -1;
    *len = ntohl(net_len);
    *data = malloc(*len);
    if(*data == NULL)
        return -1;
    if(recv_all(sock, *data, *len) != *len) {
        free(*data);
        return -1;
    }
    return 0;
}

// --- AES encryption/decryption helpers using OpenSSL EVP ---

int secure_encrypt(const unsigned char *plaintext, int plaintext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char **ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        return 0;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    int outlen1 = plaintext_len + block_size;
    *ciphertext = malloc(outlen1);
    if(*ciphertext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int len;
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int ciphertext_len_tmp = len;
    if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len_tmp += len;
    *ciphertext_len = ciphertext_len_tmp;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int secure_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        return 0;
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *plaintext = malloc(ciphertext_len);
    if(*plaintext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int len;
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int plaintext_len_tmp = len;
    if(1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len_tmp += len;
    *plaintext_len = plaintext_len_tmp;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// --- Secure send/receive: Wrap send_msg and recv_msg with AES encryption ---
int secure_send_msg(int sock, const unsigned char *plaintext, uint32_t plain_len,
                    const unsigned char *key, const unsigned char *iv) {
    unsigned char *ciphertext = NULL;
    int ciphertext_len;
    if(!secure_encrypt(plaintext, plain_len, key, iv, &ciphertext, &ciphertext_len)) {
        fprintf(stderr, "Encryption failed\n");
        return -1;
    }
    int ret = send_msg(sock, ciphertext, ciphertext_len);
    free(ciphertext);
    return ret;
}

int secure_recv_msg(int sock, unsigned char **plaintext, uint32_t *plain_len,
                    const unsigned char *key, const unsigned char *iv) {
    unsigned char *ciphertext = NULL;
    uint32_t ciphertext_len;
    if(recv_msg(sock, &ciphertext, &ciphertext_len) < 0) {
        return -1;
    }
    int decrypted_len;
    if(!secure_decrypt(ciphertext, ciphertext_len, key, iv, plaintext, &decrypted_len)) {
        free(ciphertext);
        return -1;
    }
    *plain_len = decrypted_len;
    free(ciphertext);
    return 0;
}

// --- Main client code ---
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

    // --- Key Exchange Phase ---
    // 1. Receive server's public key.
    unsigned char *server_pub_data = NULL;
    uint32_t server_pub_len;
    if(recv_msg(sockfd, &server_pub_data, &server_pub_len) < 0) {
        perror("recv_msg public key");
        exit(1);
    }
    BIO *bio = BIO_new_mem_buf(server_pub_data, server_pub_len);
    RSA *rsa_pub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(server_pub_data);
    if(!rsa_pub) {
        fprintf(stderr, "Client: error loading server public key.\n");
        exit(1);
    }
    printf("Client: received server public key.\n");

    // 2. Generate random AES key (256-bit) and encrypt it with RSA public key.
    unsigned char aes_key[32];
    if(!RAND_bytes(aes_key, 32)) {
        fprintf(stderr, "Client: RAND_bytes failed for AES key\n");
        exit(1);
    }
    unsigned char enc_aes[512];
    int enc_len = RSA_public_encrypt(32, aes_key, enc_aes, rsa_pub, RSA_PKCS1_OAEP_PADDING);
    if(enc_len == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    RSA_free(rsa_pub);
    if(send_msg(sockfd, enc_aes, enc_len) < 0) {
        perror("send_msg encrypted AES key");
        exit(1);
    }
    printf("Client: sent encrypted AES key.\n");

    // 3. Generate random IV (16 bytes) and send it.
    unsigned char iv[16];
    if(!RAND_bytes(iv, 16)) {
        fprintf(stderr, "Client: RAND_bytes failed for IV\n");
        exit(1);
    }
    if(send_msg(sockfd, iv, 16) < 0) {
        perror("send_msg IV");
        exit(1);
    }
    printf("Client: sent IV to server.\n");
    // --- End Key Exchange ---
    // Now all subsequent messages will be encrypted using AES-256-CBC with aes_key and iv.

    // --- Securely send file data ---
    if(secure_send_msg(sockfd, file_data, file_len, aes_key, iv) < 0) {
        perror("secure_send_msg file");
        exit(1);
    }
    printf("Client: sent file data (encrypted).\n");
    free(file_data);

    // --- Securely receive header ---
    unsigned char *header = NULL;
    uint32_t header_len;
    if(secure_recv_msg(sockfd, &header, &header_len, aes_key, iv) < 0) {
        perror("secure_recv_msg header");
        exit(1);
    }
    if(header_len != (4 + 64)) {
        fprintf(stderr, "Client: unexpected header length: %u\n", header_len);
        exit(1);
    }
    uint32_t total_chunks;
    memcpy(&total_chunks, header, 4);
    total_chunks = ntohl(total_chunks);
    char expected_checksum[65];
    memcpy(expected_checksum, header + 4, 64);
    expected_checksum[64] = '\0';
    free(header);
    printf("Client: header received. Total chunks: %u, checksum: %s\n", total_chunks, expected_checksum);

    // --- Receive file chunks securely ---
    ChunkData *chunks = calloc(total_chunks, sizeof(ChunkData));
    if(!chunks) { perror("calloc chunks"); exit(1); }
    uint32_t received_count = 0;
    while(received_count < total_chunks) {
        unsigned char *chunk_msg = NULL;
        uint32_t chunk_msg_len;
        if(secure_recv_msg(sockfd, &chunk_msg, &chunk_msg_len, aes_key, iv) < 0) {
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
        if(memcmp(computed_hash, chunk_msg + 4, SHA256_DIGEST_LENGTH) != 0) {
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

    // (Retransmission loop would follow similarly, using secure_send_msg and secure_recv_msg)

    // Finally, send DONE message in clear (unencrypted, if protocol specifies) or securely.
    if(send_msg(sockfd, (unsigned char*)"DONE", 4) < 0)
        perror("send_msg DONE");

    close(sockfd);
    for(uint32_t i = 0; i < total_chunks; i++) {
        if(chunks[i].data)
            free(chunks[i].data);
    }
    free(chunks);
    return 0;
}
