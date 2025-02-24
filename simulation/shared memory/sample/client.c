// Simple Client code which uses TCP over a Shared Memory

// client.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <semaphore.h>

#define SHM_NAME_C2S "/shm_client_to_server"
#define SHM_NAME_S2C "/shm_server_to_client"
#define BUFFER_SIZE 1048576

#define SEM_C2S_DATA "/sem_c2s_data"
#define SEM_C2S_SPACE "/sem_c2s_space"
#define SEM_S2C_DATA "/sem_s2c_data"
#define SEM_S2C_SPACE "/sem_s2c_space"

typedef struct {
    size_t msg_len;
    char data[BUFFER_SIZE - sizeof(size_t)];
} Message;

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        exit(1);
    }
    const char *file_path = argv[1];
    FILE *fp = fopen(file_path, "rb");
    if(!fp) { perror("fopen"); exit(1); }
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);
    char *file_data = malloc(file_size);
    if(fread(file_data, 1, file_size, fp) != file_size) {
        perror("fread");
        exit(1);
    }
    fclose(fp);
    printf("Client: read file of %zu bytes.\n", file_size);

    // Open shared memory segments
    int fd_c2s = shm_open(SHM_NAME_C2S, O_RDWR, 0666);
    if(fd_c2s < 0) { perror("shm_open client_to_server"); exit(1); }
    Message *c2s = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_c2s, 0);
    if(c2s == MAP_FAILED) { perror("mmap client_to_server"); exit(1); }

    int fd_s2c = shm_open(SHM_NAME_S2C, O_RDWR, 0666);
    if(fd_s2c < 0) { perror("shm_open server_to_client"); exit(1); }
    Message *s2c = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_s2c, 0);
    if(s2c == MAP_FAILED) { perror("mmap server_to_client"); exit(1); }

    // Open semaphores
    sem_t *sem_c2s_data = sem_open(SEM_C2S_DATA, 0);
    sem_t *sem_c2s_space = sem_open(SEM_C2S_SPACE, 0);
    sem_t *sem_s2c_data = sem_open(SEM_S2C_DATA, 0);
    sem_t *sem_s2c_space = sem_open(SEM_S2C_SPACE, 0);
    if(sem_c2s_data == SEM_FAILED || sem_c2s_space == SEM_FAILED ||
       sem_s2c_data == SEM_FAILED || sem_s2c_space == SEM_FAILED) {
        perror("sem_open");
        exit(1);
    }

    // Send file data
    sem_wait(sem_c2s_space);
    size_t to_send = file_size < (BUFFER_SIZE - sizeof(size_t)) ? file_size : (BUFFER_SIZE - sizeof(size_t));
    c2s->msg_len = to_send;
    memcpy(c2s->data, file_data, to_send);
    sem_post(sem_c2s_data);
    printf("Client: sent file data (%zu bytes).\n", to_send);

    // Wait for header from server
    sem_wait(sem_s2c_data);
    if(s2c->msg_len != sizeof(size_t)) {
        printf("Client: unexpected header length: %zu\n", s2c->msg_len);
    } else {
        size_t header;
        memcpy(&header, s2c->data, sizeof(size_t));
        printf("Client: received header. Server indicates file size: %zu bytes.\n", header);
    }
    sem_post(sem_s2c_space);

    munmap(c2s, BUFFER_SIZE);
    munmap(s2c, BUFFER_SIZE);
    close(fd_c2s);
    close(fd_s2c);
    sem_close(sem_c2s_data);
    sem_close(sem_c2s_space);
    sem_close(sem_s2c_data);
    sem_close(sem_s2c_space);
    free(file_data);
    return 0;
}
