// Simple server code which uses TCP over a Shared Memory

// server.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <semaphore.h>
#include <time.h>

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

// Error simulation parameters (set to 0 for testing)
double drop_prob = 0.0;
double corrupt_prob = 0.0;

void simulate_error(char *msg, size_t total_len) {
    double r = (double)rand() / RAND_MAX;
    if(r < drop_prob) {
        printf("[Server] Simulating drop of message.\n");
        // To simulate drop, we simply do not send (or set msg_len=0)
        ((Message*)msg)->msg_len = 0;
    } else if(r < drop_prob + corrupt_prob) {
        printf("[Server] Simulating corruption of message.\n");
        if(total_len > sizeof(size_t)) {
            msg[sizeof(size_t)] ^= 0xFF;  // flip one bit in payload
        }
    }
}

int main(void) {
    srand(time(NULL));
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

    printf("Server: waiting for message from client...\n");
    sem_wait(sem_c2s_data);
    size_t msg_len = c2s->msg_len;
    if(msg_len == 0) {
        printf("Server: No data received (message dropped).\n");
        sem_post(sem_c2s_space);
        exit(0);
    }
    printf("Server: received message of %zu bytes.\n", msg_len);

    // For demonstration, send a header back containing the received length.
    sem_wait(sem_s2c_space);
    s2c->msg_len = sizeof(size_t);
    memcpy(s2c->data, &msg_len, sizeof(size_t));
    simulate_error((char*)s2c, s2c->msg_len + sizeof(size_t));
    sem_post(sem_s2c_data);
    sem_post(sem_c2s_space);
    printf("Server: sent header.\n");

    munmap(c2s, BUFFER_SIZE);
    munmap(s2c, BUFFER_SIZE);
    close(fd_c2s);
    close(fd_s2c);
    sem_close(sem_c2s_data);
    sem_close(sem_c2s_space);
    sem_close(sem_s2c_data);
    sem_close(sem_s2c_space);
    return 0;
}
