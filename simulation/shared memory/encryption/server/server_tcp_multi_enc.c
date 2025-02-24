// encryption/server/server_tcp_multi_enc.c 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>

#define TCP_PORT 5001
#define CHUNK_SIZE_SMALL 1024
#define CHUNK_SIZE_LARGE (1024*1024)
double DROP_PROB = 0.2;
double CORRUPT_PROB = 0.1;

/* Helper functions: send_all and recv_all */
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

/* Message framing: 4-byte length prefix */
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
    if(*data == NULL) return -1;
    if(recv_all(sock, *data, *len) != *len) {
        free(*data);
        return -1;
    }
    return 0;
}

/* AES encryption/decryption helpers using OpenSSL EVP */
int secure_encrypt(const unsigned char *plaintext, int plaintext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char **ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    int outbuf_len = plaintext_len + block_size;
    *ciphertext = malloc(outbuf_len);
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
    int total_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int secure_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
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
    int total_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;
    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

/* Secure send/receive wrappers */
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
    if(recv_msg(sock, &ciphertext, &ciphertext_len) < 0)
        return -1;
    int dec_len;
    if(!secure_decrypt(ciphertext, ciphertext_len, key, iv, plaintext, &dec_len)) {
        free(ciphertext);
        return -1;
    }
    *plain_len = dec_len;
    free(ciphertext);
    return 0;
}

/* RSA Private Key Loader */
RSA* load_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if(!fp) { perror("fopen private key"); return NULL; }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

/* Structure for a file chunk */
typedef struct {
    uint32_t seq;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char *data;
    uint32_t data_len;
} Chunk;

/* Thread function: handle one client connection */
void *handle_client(void *arg) {
    int conn = *(int*)arg;
    free(arg);

    // --- Key Exchange Phase ---
    RSA *rsa_priv = load_private_key("server_private.pem");
    if(!rsa_priv) {
        fprintf(stderr, "Error loading RSA private key\n");
        close(conn);
        pthread_exit(NULL);
    }
    FILE *pub_fp = fopen("server_public.pem", "r");
    if(!pub_fp) {
        perror("fopen public key");
        RSA_free(rsa_priv);
        close(conn);
        pthread_exit(NULL);
    }
    fseek(pub_fp, 0, SEEK_END);
    long pub_len = ftell(pub_fp);
    rewind(pub_fp);
    unsigned char *pub_data = malloc(pub_len);
    if(fread(pub_data, 1, pub_len, pub_fp) != pub_len) {
        perror("fread public key");
        free(pub_data);
        fclose(pub_fp);
        RSA_free(rsa_priv);
        close(conn);
        pthread_exit(NULL);
    }
    fclose(pub_fp);
    if(send_msg(conn, pub_data, pub_len) < 0) {
        perror("send_msg public key");
        free(pub_data);
        RSA_free(rsa_priv);
        close(conn);
        pthread_exit(NULL);
    }
    free(pub_data);
    printf("Server: Sent public key to client.\n");

    unsigned char *enc_aes = NULL;
    uint32_t enc_aes_len;
    if(recv_msg(conn, &enc_aes, &enc_aes_len) < 0) {
        perror("recv_msg encrypted AES key");
        RSA_free(rsa_priv);
        close(conn);
        pthread_exit(NULL);
    }
    unsigned char aes_key[32];
    int dec_len = RSA_private_decrypt(enc_aes_len, enc_aes, aes_key, rsa_priv, RSA_PKCS1_OAEP_PADDING);
    if(dec_len != 32) {
        fprintf(stderr, "AES key decryption failed\n");
        free(enc_aes);
        RSA_free(rsa_priv);
        close(conn);
        pthread_exit(NULL);
    }
    free(enc_aes);
    RSA_free(rsa_priv);
    printf("Server: Key exchange complete. AES key established.\n");

    unsigned char *iv_alloc = NULL;
    uint32_t iv_len;
    if(recv_msg(conn, &iv_alloc, &iv_len) < 0 || iv_len != 16) {
        fprintf(stderr, "Failed to receive IV\n");
        close(conn);
        pthread_exit(NULL);
    }
    unsigned char iv[16];
    memcpy(iv, iv_alloc, 16);
    free(iv_alloc);
    printf("Server: IV received from client.\n");
    // --- End Key Exchange ---

    // --- Securely receive file data ---
    unsigned char *file_data = NULL;
    uint32_t file_len_val;
    if(secure_recv_msg(conn, &file_data, &file_len_val, aes_key, iv) < 0) {
        perror("secure_recv_msg file data");
        close(conn);
        pthread_exit(NULL);
    }
    printf("Server: Received encrypted file of %u bytes.\n", file_len_val);

    // --- Determine chunk size and split file ---
    uint32_t chunk_size = (file_len_val > 100*1024*1024) ? CHUNK_SIZE_LARGE : CHUNK_SIZE_SMALL;
    uint32_t total_chunks = (file_len_val + chunk_size - 1) / chunk_size;
    printf("Server: Splitting file into %u chunks (chunk size %u bytes).\n", total_chunks, chunk_size);

    // --- Compute overall file checksum ---
    unsigned char overall_hash[SHA256_DIGEST_LENGTH];
    SHA256(file_data, file_len_val, overall_hash);
    char overall_hash_hex[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&overall_hash_hex[i*2], "%02x", overall_hash[i]);
    overall_hash_hex[64] = '\0';

    // --- Securely send header (total_chunks and overall checksum) ---
    uint32_t header_len = 4 + 64;
    unsigned char *header = malloc(header_len);
    if(!header) { perror("malloc header"); close(conn); pthread_exit(NULL); }
    uint32_t net_total = htonl(total_chunks);
    memcpy(header, &net_total, 4);
    memcpy(header+4, overall_hash_hex, 64);
    if(secure_send_msg(conn, header, header_len, aes_key, iv) < 0) {
        perror("secure_send_msg header");
        free(header);
        close(conn);
        pthread_exit(NULL);
    }
    printf("Server: Sent header with total_chunks=%u and checksum=%s\n", total_chunks, overall_hash_hex);
    free(header);

    // --- Split file into chunks ---
    Chunk *chunks = malloc(total_chunks * sizeof(Chunk));
    if(!chunks) { perror("malloc chunks"); close(conn); pthread_exit(NULL); }
    for(uint32_t i = 0; i < total_chunks; i++) {
        chunks[i].seq = i;
        uint32_t start = i * chunk_size;
        uint32_t this_chunk_size = (start + chunk_size <= file_len_val) ? chunk_size : (file_len_val - start);
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

    // --- Securely send chunks in shuffled order with error simulation ---
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
        if(secure_send_msg(conn, msg, msg_len, aes_key, iv) < 0) {
            perror("secure_send_msg chunk");
            free(msg);
            break;
        }
        free(msg);
    }
    free(indices);
    printf("Server: Initial transmission complete.\n");

    // --- Retransmission Loop (up to 5 rounds) ---
    int rounds = 0;
    while(rounds < 5) {
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        unsigned char *req_msg = NULL;
        uint32_t req_len;
        if(recv_msg(conn, &req_msg, &req_len) < 0)
            break;
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
                if(secure_send_msg(conn, msg, msg_len, aes_key, iv) < 0) {
                    perror("secure_send_msg retransmit");
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

    // Cleanup chunks.
    for(uint32_t i = 0; i < total_chunks; i++) {
        free(chunks[i].data);
    }
    free(chunks);
    close(conn);
    printf("Server: Connection closed.\n");
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
    printf("TCP Server (encrypted, multi-client) listening on port %d...\n", TCP_PORT);

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
