#include <stdint.h>
#include <stdlib.h>
#include "exec/hwaddr.h"

extern size_t input_index;
extern size_t last_input_index;
extern uint8_t first_mmio_read;
extern uint8_t drifuzz_loaded;

void drifuzz_loop(void);
void drifuzz_reset(void);
uint8_t  get_byte(void);
uint16_t get_word(void);
uint32_t get_dword(void);
uint64_t get_qword(void);

static inline uint64_t get_data(unsigned size) {
    switch (size)
    {
    case 1:
        return (uint64_t)get_byte();
    case 2:
        return (uint64_t)get_word();
    case 4:
        return (uint64_t)get_dword();
    case 8:
        return (uint64_t)get_qword();
    default:
        return 0;
    }
}

void handle_dma_init(void *opaque, uint64_t dma, uint64_t phy, 
		uint64_t size, int consistent);
void handle_dma_exit(void *opaque, uint64_t dma, int consistent);
void handle_exec_init(void);
void handle_exec_exit(void);
void handle_exec_timeout(void);
void handle_submit_stage(uint64_t);
void* get_dma_buffer(uint64_t);
void handle_submit_kcov_trace(uint64_t trace, uint64_t size);
void handle_guest_kasan(void);
void handle_req_reset(void);

void drifuzz_open_bitmap(char* fn, uint64_t size);
void drifuzz_setup_timeout(int sec) ;

/* Communicator */
void communicate_write(uint64_t region, uint64_t address,
        uint64_t size, uint64_t val);

uint64_t communicate_read(uint64_t region, uint64_t address,
        uint64_t size);
void* communicate_dma_buffer(uint64_t size);

void communicate_exec_init(void);
void communicate_exec_exit(void);
void communicate_exec_timeout(void);
void communicate_ready(uint64_t*);
void communicate_guest_kasan(void);
void communicate_req_reset(void);

void drifuzz_setup_socket(char* socket_path);
void drifuzz_set_timeout(int);

/* Op callbacks */
struct drifuzz_dma_ops {
    uint64_t (*const_dma_read)(void *opaque, hwaddr addr,
            unsigned size);
    void (*const_dma_write)(void *opaque, hwaddr addr,
            uint64_t val, unsigned size);
    void* (*get_stream_dma)(uint64_t size);
};
void drifuzz_reg_dma_ops(const struct drifuzz_dma_ops* ops);

struct drifuzz_hw_ops {
    void (*reset)(void);
};
void drifuzz_reg_hw_ops(const struct drifuzz_hw_ops *op);

struct dma_desc {
    void* opaque;       // hw opaque
    uint32_t id;
    size_t size;
    int type;           // 1 for consistent 2 for stream
};