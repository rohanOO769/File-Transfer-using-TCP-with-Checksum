// manager_server.c

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <unistd.h>
#include <string.h>

#define SHM_NAME_C2S "/shm_client_to_server"
#define SHM_NAME_S2C "/shm_server_to_client"
#define BUFFER_SIZE 1048576  // 1 MB

// Semaphore names
#define SEM_C2S_DATA "/sem_c2s_data"
#define SEM_C2S_SPACE "/sem_c2s_space"
#define SEM_S2C_DATA "/sem_s2c_data"
#define SEM_S2C_SPACE "/sem_s2c_space"

// Structure for our shared memory message
typedef struct {
    size_t msg_len;  // Stores message length
    char data[BUFFER_SIZE - sizeof(size_t)];
} Message;

int main(void) {
    // Create/open shared memory for client-to-server
    int fd_c2s = shm_open(SHM_NAME_C2S, O_CREAT | O_RDWR, 0666);
    if (fd_c2s < 0) { perror("shm_open client_to_server"); exit(1); }
    if (ftruncate(fd_c2s, BUFFER_SIZE) == -1) { perror("ftruncate client_to_server"); exit(1); }
    Message *c2s = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_c2s, 0);
    if (c2s == MAP_FAILED) { perror("mmap client_to_server"); exit(1); }
    memset(c2s, 0, BUFFER_SIZE);

    // Create/open shared memory for server-to-client
    int fd_s2c = shm_open(SHM_NAME_S2C, O_CREAT | O_RDWR, 0666);
    if (fd_s2c < 0) { perror("shm_open server_to_client"); exit(1); }
    if (ftruncate(fd_s2c, BUFFER_SIZE) == -1) { perror("ftruncate server_to_client"); exit(1); }
    Message *s2c = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_s2c, 0);
    if (s2c == MAP_FAILED) { perror("mmap server_to_client"); exit(1); }
    memset(s2c, 0, BUFFER_SIZE);

    // Create/open semaphores for synchronization
    sem_t *sem_c2s_data = sem_open(SEM_C2S_DATA, O_CREAT, 0666, 0);
    sem_t *sem_c2s_space = sem_open(SEM_C2S_SPACE, O_CREAT, 0666, 1);
    sem_t *sem_s2c_data = sem_open(SEM_S2C_DATA, O_CREAT, 0666, 0);
    sem_t *sem_s2c_space = sem_open(SEM_S2C_SPACE, O_CREAT, 0666, 1);
    if (sem_c2s_data == SEM_FAILED || sem_c2s_space == SEM_FAILED ||
        sem_s2c_data == SEM_FAILED || sem_s2c_space == SEM_FAILED) {
        perror("sem_open");
        exit(1);
    }

    printf("Manager server started on port 50000.\n");
    printf("Shared memory and semaphores initialized.\n");
    printf("Press Ctrl+C to terminate the manager server.\n");

    // Keep the manager running indefinitely
    while (1) {
        sleep(1);
    }

    // Cleanup code (unreachable in this example)
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
