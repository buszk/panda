#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <assert.h>

#include "kcov-trace.h"
#include "drifuzz.h"

void cpu_physical_memory_rw(uint64_t addr, uint8_t *buf,
                            uint64_t len, int is_write);

static uint8_t *addr = NULL;
static uint32_t len = 0;
static uint8_t *cur = NULL;

static uint8_t *dma_addr = NULL;
static uint8_t *dma_cur = NULL;


static uint8_t *bitmap = NULL;
static uint64_t bitmap_size = 0;

static int init = 0;
static int fuzz_mode = 1;

size_t last_input_index = -1;
size_t input_index = 0;


static void __attribute__((constructor)) open_seed(void) {
    int fd, ret;
    struct stat st;
    fd = open("random_seed", O_RDONLY);
    if((ret=fstat(fd,&st)) < 0)
        perror("Error in fstat");
    len = st.st_size;
    printf("Len: %d\n", len);
    if (len > 4096)
        len = 4096;
    if((addr=mmap(NULL,len,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0)) == MAP_FAILED)
        perror("Error in mmap");
    close(fd);
    cur = addr;
    fd = open("/dev/zero", O_RDONLY);
    if ((dma_addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        perror("Error in mmap");
    memset(dma_addr, 0x41, 4096);
    close(fd);
    
    dma_cur = dma_addr;
}

static void __attribute__((destructor)) close_seed(void) {
    if (munmap(addr,len) == -1)
        perror("Error in munmap");
}

static int timeout_sec = 0;
static int timeout_matter = 0; // 1 sync, 2 exec

static void timeout_cb(int sig) {
    switch (timeout_matter) {
        case 1:
            communicate_req_reset();
            break;
        case 2:
            handle_exec_timeout();
            break;
        default:
            assert(0);
    }
}

void drifuzz_set_timeout(int sec) {
    timeout_sec = sec;
    signal(SIGALRM, timeout_cb);
}

void drifuzz_open_bitmap(char* fn, uint64_t size) {
    int fd;
    if ((fd = open(fn, O_CREAT|O_RDWR|O_SYNC, 0777)) < 0)
        perror("open");
    if ((bitmap = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == 0)
        perror("mmap"), fuzz_mode = 0;
    bitmap_size = size;
}

uint8_t  get_byte(void) {
    uint8_t ret = *((uint8_t *)cur);
    cur += 1;
    if (cur+1 > addr + len)
        cur = addr;
    return ret;
}
uint16_t get_word(void) {
    uint16_t ret = *((uint16_t *)cur);
    cur += 2;
    if (cur+2 > addr + len)
        cur = addr;
    // printf("get_word: %x\n", ret);
    return ret;
}
uint32_t get_dword(void) {
    uint32_t ret = *((uint32_t *)cur);
    cur += 4;
    if (cur+4 > addr + len)
        cur = addr;
    // printf("get_dword: %x\n", ret);
    return ret;
}
uint64_t get_qword(void) {
    uint64_t ret = *((uint64_t *)cur);
    cur += 8;
    if (cur+8 > addr + len)
        cur = addr;
    // printf("get_qword: %lx\n", ret);
    return ret;
}

void start_sync_timer(void) {
    timeout_matter = 1;
    alarm(1);
}

void start_exec_timer(void) {
    timeout_matter = 2;
    alarm(timeout_sec);
}

void handle_exec_init(void) {
    // TODO: reset file
    if (!init) {
        init = 1;
        uint64_t key;
        communicate_ready(&key);
        // snapshots
        save_vmstate(NULL, "test");
        printf("vmstate stored\n");
    }
    if (fuzz_mode)
        memset(bitmap, 255, bitmap_size);
    cur = addr;
    communicate_exec_init();
    printf("handle_exec_init\n");
    start_sync_timer();
    // When guest driver continue to execute
    // It will call start_exec_timer in fuzzer.c
}

void handle_exec_exit(void) {
    printf("handle_exec_exit\n");
    copy_trace_from_guest(bitmap);
    communicate_exec_exit();
    alarm(0);
    printf("handle_exec_exit ends\n");

    // snapshots
    if (fuzz_mode) {
        load_vmstate("test");
        memset(bitmap, 255, bitmap_size);
    }
    cur = addr;
    communicate_exec_init();
    start_exec_timer();
}

void handle_exec_timeout(void) {
    printf("handle_exec_timeout\n");
    if (fuzz_mode) {
        copy_trace_from_guest(bitmap);
    }
    communicate_exec_timeout();
    printf("handle_exec_timeout ends\n");
}

void handle_submit_stage(uint64_t stage) {
    printf("handle_submit_stage %ld\n", stage);
}

void handle_submit_kcov_trace(uint64_t kcov_trace, uint64_t size)  {
    printf("handle_submit_kcov_trace %p %lx\n", (void*)kcov_trace, size);
    register_trace_page(kcov_trace);
}

void handle_guest_kasan(void) {
    printf("handle_guest_kasan\n");
    if (init && fuzz_mode)
        copy_trace_from_guest(bitmap);
    communicate_guest_kasan();
    if (!init) 
        return;
    alarm(0);


    // snapshots
    load_vmstate("test");
    printf("vmstate loaded\n");
    // handle_exec_init();
    if (fuzz_mode)
        memset(bitmap, 255, bitmap_size);
    cur = addr;
    communicate_exec_init();
    start_exec_timer();
}

void handle_req_reset(void) {
    printf("handle_req_reset\n");
    communicate_req_reset();
}

void* get_dma_buffer(uint64_t size) {
    return (void*) dma_cur;
}
