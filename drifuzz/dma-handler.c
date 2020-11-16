#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/hw.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include "qemu/module.h"
#include "qemu/range.h"
#include "qapi/error.h"
#include "panda/rr/rr_log_all.h"
#include "panda/rr/rr_log.h"

#include "drifuzz.h"

#define DRIFUZZ_PRIORITY 100
#define UNUSED __attribute__((unused))

struct tracked_region {
    MemoryRegion *region;
    uint64_t dma;
    struct tracked_region *next, *prev;
};
static struct tracked_region *tracked_list = NULL;
static size_t count = 0;
static uint64_t const_cnt = 0;
static int registered = 0;


static __attribute__((unused)) void check_list(void) {
    struct tracked_region *track;
    size_t size = 0;
    for (track = tracked_list; track; track = track->next) {
        size ++;
    }
    if (size != count) {
        printf("BUG\n size %lu count %lu\n", size, count);
    }
}

static __attribute__((unused)) struct tracked_region * search_region(uint64_t dma) {
    struct tracked_region *track;
    for (track = tracked_list; track; track = track->next) {
        if (track->dma == dma) {
            return track;
        }
        else if (track->dma < dma && dma < track->dma + track->region->size) {
            printf("return overlap\n");
            return track;
        }
    }
    return NULL;
}

static void add_region(MemoryRegion *region, uint64_t dma) {
    struct tracked_region *track;
#ifdef ALWAYS_TRACK
    track = search_region(dma);
    if (track) {
        assert(track->exited == 1);
        assert(track->region->addr == region->addr);
        assert(track->region->size == region->size);
        track->exited = 0;
        return;
    }
#endif
    track = malloc(sizeof(*track));
    track->region = region;
    track->dma = dma;

#ifdef ALWAYS_TRACK
    track->exited = 0;
#endif
    track->next = tracked_list;
    track->prev = NULL;
    if (tracked_list) {
        tracked_list->prev = track;
    }
    tracked_list = track;
    count ++;
}

static UNUSED MemoryRegion* rm_region(uint64_t dma) {
    struct tracked_region *track;
    MemoryRegion *ret;
    track = tracked_list;
    for (track = tracked_list; track; track = track->next) {
        if (track->dma == dma) {
            if (track->prev)
                track->prev->next = track->next;
            if (track->next) 
                track->next->prev = track->prev;
            if (track == tracked_list) {
                tracked_list = track->next;
            }
            ret = track->region;
            free(track);
            count --;
            return ret;
        }
    }
    return NULL;
}

static UNUSED uint64_t read_mem (void* mem, hwaddr addr, unsigned size) {
	uint8_t *offset_addr = (uint8_t*) mem + addr;
	switch (size)
	{
	case 1:
		return *(uint8_t*)offset_addr;
	case 2:
		return *(uint16_t*)offset_addr;
	case 4:
		return *(uint32_t*)offset_addr;
	case 8:
		return *(uint64_t*)offset_addr;
	default:
		assert("wrong size" && false);
		return 0;
	}
}

static UNUSED void write_mem (void* mem, hwaddr addr, uint64_t val, unsigned size) {
	uint8_t *offset_addr = (uint8_t*) mem + addr;
	switch (size)
	{
	case 1:
		*(uint8_t*)offset_addr = val & 0xff;
		break;
	case 2:
		*(uint16_t*)offset_addr = val & 0xffff;
		break;
	case 4:
		*(uint32_t*)offset_addr = val & 0xffffffff;
		break;
	case 8:
		*(uint64_t*)offset_addr = val;
		break;
	default:
		assert("wrong size" && false);
		break;
	}
}

static uint64_t (*__const_dma_read)(void*, hwaddr, unsigned);
static void (*__const_dma_write)(void*, hwaddr, uint64_t, unsigned);
static void* (*__get_stream_dma)(uint64_t);

void drifuzz_reg_dma_ops(const struct drifuzz_dma_ops * ops) {
    registered = 1;
    __const_dma_read = ops->const_dma_read;
    __const_dma_write = ops->const_dma_write;
    __get_stream_dma = ops->get_stream_dma ? 
            ops->get_stream_dma : communicate_dma_buffer;
}

static uint64_t const_dma_read(void *opaque, hwaddr addr,
                              unsigned size) {
    
    struct dma_desc *desc = opaque;
	uint64_t ret = __const_dma_read(opaque, addr, size);
    
    printf("const_dma_read[id:%d]: %lx[%u] returns %lx\n", desc->id, addr, size, ret);

    return ret;
}


static void const_dma_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size) {
    struct dma_desc *desc = opaque;
    if (val != 0)
	    printf("const_dma_write[id:%d]: %lx[%u]=%lx \n", desc->id, addr, size, val);
    __const_dma_write(opaque, addr, val, size);
    // communicate_write(2, addr, size, val);
    //write_mem(opaque, addr, val, size);
}
static UNUSED const MemoryRegionOps const_dma_ops = {
    .read = const_dma_read,
    .write = const_dma_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t stream_dma_read(void *opaque, hwaddr addr,
                              unsigned size) {

	uint64_t ret = get_data(size);
    printf("stream_dma_read: %lx[%u] returns %lx\n", addr, size, ret);

    return ret;
}

static void stream_dma_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size) {
	printf("stream_dma_write: %lx[%u]=%lx \n", addr, size, val);
}

static UNUSED const MemoryRegionOps stream_dma_ops = {
    .read = stream_dma_read,
    .write = stream_dma_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

void handle_dma_init(void *opaque, uint64_t dma, uint64_t phy, 
		uint64_t size, int consistent) {
    if (!registered) return;
    if (consistent)
    	printf("const_dma_init opaque:[%p] dma[%lx] phy[%lx]\n",opaque, dma, phy);
#ifdef ALWAYS_TRACK
    struct tracked_region * track;
    track = search_region(dma);
    if (track) {
        assert(track->exited);
        assert(track->region->addr == phy);
        assert(track->region->size == size);
        track->exited = 0;
        num_exit --;
        return;
    }
#endif
	MemoryRegion *subregion;
	subregion = malloc(sizeof(*subregion));
    subregion->size = size;
    add_region(subregion, dma);
    /* stream dma are not tracked */
    // if(false) {
    if (consistent) {
        struct dma_desc *desc = malloc(sizeof(struct dma_desc));
        desc->id = const_cnt ++;
        desc->opaque = opaque;
        desc->size = size;
        desc->type = 1;
        if (rr_in_replay()) {
            rr_replay_skipped_calls();
        }
        rr_record_mem_region_change = 0;
        printf("init_io\n");
        memory_region_init_io(subregion, OBJECT(opaque), 
                consistent ? &const_dma_ops: &stream_dma_ops,
                desc, "drifuzz-dma-region", size);
        memory_region_add_subregion_overlap(get_system_memory(),
                phy, subregion, DRIFUZZ_PRIORITY);
        printf("init_io done\n");
        rr_record_mem_region_change = 1;
    }
}

void handle_dma_exit(void *opaque, uint64_t dma, int consistent) {
    if (!registered) return;
    if (consistent)
    	printf("const_dma_exit opaque:[%p] dma[%lx]\n",opaque, dma);
#ifdef ALWAYS_TRACK
    struct tracked_region *track;
    track = search_region(dma);
    if (!track || track->exited == 1) {
        printf("dma_exit: invalid dma address\n");
        return;
    }
    track->exited = 1;
    num_exit ++;
#else

    check_list();
    MemoryRegion *subregion;
    subregion = rm_region(dma);
    if (!subregion) {
	    printf("dma_exit: invalid dma address\n");
        return;
    }
    // if (false) {
    if (consistent) {
        // Is this the proper way to deallocate subregion? 
        rr_record_mem_region_change = 0;
        memory_region_del_subregion(get_system_memory(), subregion);
        rr_record_mem_region_change = 1;
        object_unparent(OBJECT(subregion));

        // free(subregion);
    }
    else {
        /* Put random bytes to stream dma buffer */
        // TODO: check if success. dma_memory_write should be quick in qemu tho
        RR_DO_RECORD_OR_REPLAY(
            do {
                void *dma_buf = __get_stream_dma(subregion->size);
                dma_memory_write(&address_space_memory, dma,
                        dma_buf, subregion->size);
                free(dma_buf);
            } while (0),
            RR_NO_ACTION,
            RR_NO_ACTION,
            RR_CALL_CPU_MEM_RW);
        free(subregion);
    }
    
    
#endif

}
