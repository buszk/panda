#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include "panda/rr/rr_log.h"
#include "drifuzz.h"
struct sockaddr_un addr;
int fd,rc;
int ifd;
int inited = 0;

extern char *index_path;

enum Command{
    WRITE = 1,
    READ,
    DMA_BUF,
    EXEC_INIT,
    EXEC_EXIT,
    READY,
    VM_KASAN,
    VM_REQ_RESET,
    EXEC_TIMEOUT,
};
void drifuzz_setup_socket(char* socket_path) {
    if (!socket_path)
        return;
    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }
    addr.sun_family = AF_UNIX;
    if (*socket_path == '\0') {
        *addr.sun_path = '\0';
        strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
    } else {
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(-1);
    }
}

static void  _init(void) {
    printf("[communicator] index_path: %s\n", index_path);
    if ((ifd = open(index_path, O_CREAT|O_TRUNC|O_WRONLY, 0644)) < 0)
        perror("open index file failed"), exit(-1);
    inited = 1;
}


static void __attribute__((destructor)) _fini(void);
static void __attribute__((destructor)) _fini(void) {
    close(fd);
    close(ifd);
}

void communicate_write(uint64_t region, uint64_t address,
        uint64_t size, uint64_t val) {
    uint64_t buf[] = { WRITE, region, address, size, val};
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_write: write"), exit(1);
}

uint64_t communicate_read(uint64_t region, uint64_t address,
        uint64_t size) {
    uint64_t res;
    uint64_t idx;
    uint64_t buf[] = { READ, region, address, size};
    if (write(fd, buf, sizeof(buf)) != sizeof(buf))
        perror("communicate_read: write"), exit(1);
    if (read(fd, &res, sizeof(res)) != sizeof(res))
        perror("communicate_read: read"), exit(1);
    if (read(fd, &idx, sizeof(idx)) != sizeof(idx))
        perror("communicate_dma_buffer: read"), exit(1);
    if (!inited) _init();
    dprintf(ifd, "input_index: %lx, seed_index: %lx, size: %d, address: %lx, region: %d, rr_count: %lx\n",
            input_index, idx, size, address, region, rr_get_guest_instr_count());
    return res;
}

void* communicate_dma_buffer(uint64_t size) {
    void* res = malloc(size);
    uint64_t idx;
    uint64_t buf[] = {DMA_BUF, size};
    if (write(fd, buf, sizeof(buf)) != sizeof(buf))
        perror("communicate_dma_buffer: write"), exit(1);
    if (read(fd, res, size) != size)
        perror("communicate_dma_buffer: read"), exit(1);
    if (read(fd, &idx, sizeof(idx)) != sizeof(idx))
        perror("communicate_dma_buffer: read"), exit(1);
    if (!inited) _init();
    dprintf(ifd, "input_index: %lx, seed_index: %lx, size: %d\n", 
            input_index, idx, size);

    return res;
}

void communicate_exec_init(void) {
    uint64_t buf[] = {EXEC_INIT};
    uint64_t syn;
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_exec_init: write"), exit(1);
    if (read(fd, &syn, sizeof(syn)) != sizeof(syn)) 
        perror("communicate_exec_init: read"), exit(1);
}

void communicate_exec_exit(void) {
    uint64_t buf[] = {EXEC_EXIT};
    uint64_t syn;
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_exec_exit: write"), exit(1);
    if (read(fd, &syn, sizeof(syn)) != sizeof(syn)) 
        perror("communicate_exec_exit: read"), exit(1);
}

void communicate_exec_timeout(void) {
    uint64_t buf[] = {EXEC_TIMEOUT};
    uint64_t syn;
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_exec_timeout: write"), exit(1);
    if (read(fd, &syn, sizeof(syn)) != sizeof(syn)) 
        perror("communicate_exec_timeout: read"), exit(1);
    // Server side will just disconnect, no wait for ack
    // close(fd);
    // exit(0);
}

void communicate_ready(uint64_t* syn) {
    uint64_t buf[] = {READY};
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_ready: write"), exit(1);
    if (read(fd, syn, sizeof(*syn)) != sizeof(*syn)) 
        perror("communicate_ready: read"), exit(1);
}

void communicate_guest_kasan(void) {
    uint64_t buf[] = {VM_KASAN};
    uint64_t syn;
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_guest_kasan: write"), exit(1);
    if (read(fd, &syn, sizeof(syn)) != sizeof(syn)) 
        perror("communicate_guest_kasan: read"), exit(1);
    // Try ending replay
    panda_replay_end();
    // printf("Communiator: Exiting!!!\n");
    // close(fd);
    // exit(0);
    // printf("Communiator: BUG!!!\n");
}

void communicate_req_reset(void) {
    uint64_t buf[] = {VM_REQ_RESET};
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        perror("communicate_req_reset: write"), exit(1);
    // Server side will just disconnect, no wait for ack
    close(fd);
    exit(0);
}
