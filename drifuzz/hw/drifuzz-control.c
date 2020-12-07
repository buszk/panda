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

#include "drifuzz.h"

/* shared */
enum ACTIONS {
	CONST_DMA_INIT = 1,
	CONST_DMA_EXIT,
	STREAM_DMA_INIT,
	STREAM_DMA_EXIT,
    EXEC_INIT,
    EXEC_EXIT,
    SUBMIT_STAGE,
	SUBMIT_KCOV_TRACE,
	KASAN,
	REQ_RESET,
	EXEC_TIMEOUT,
};

typedef struct DMAAction_t {
	uint64_t dma;
	uint64_t phy;
	uint64_t size;
	uint8_t alloc;
	uint8_t consistent;
} DMAAction;

typedef struct DrifuzzState_t {
	PCIDevice parent_obj;
	
	MemoryRegion mmio;
	size_t input_index_save;
	char memory [0x1000];

	uint8_t actions[sizeof(DMAAction) * 0x1000];
	size_t actions_count;
	
	char *socket_path;
	char *bitmap_file;
	uint64_t bitmap_size;
	uint64_t timeout_sec;
	char *target_name;
	char *prog_name;

} DrifuzzState;

uint8_t dma_used = 0;

typedef struct DrifuzzClass {
	PCIDeviceClass parent_class;
} DrifuzzClass;

#define DRIFUZZ(obj) \
	OBJECT_CHECK(DrifuzzState, (obj), TYPE_PCI_DEVICE)

static void drifuzz_class_init(ObjectClass *klass, void *data);
static void pci_drifuzz_realize(PCIDevice *pci_dev, Error **errp);
static void drifuzz_instance_init(Object *obj);
static void drifuzz_register_types(void);
static const MemoryRegionOps drifuzz_mmio_ops;
static void(*drifuzz_device_reset)(void);

static Property drifuzz_properties[] = {
	DEFINE_PROP_STRING("socket", DrifuzzState, socket_path),
	DEFINE_PROP_STRING("bitmap", DrifuzzState, bitmap_file),
	DEFINE_PROP_UINT64("bitmap_size", DrifuzzState, bitmap_size, 65536),
	DEFINE_PROP_UINT64("timeout", DrifuzzState, timeout_sec, 20),
	DEFINE_PROP_STRING("target", DrifuzzState, target_name),
	DEFINE_PROP_STRING("prog", DrifuzzState, prog_name),
	DEFINE_PROP_END_OF_LIST(),
};

static uint64_t read_mem (char* mem, hwaddr addr, unsigned size) {
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

static void write_mem (char* mem, hwaddr addr, uint64_t val, unsigned size) {
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

static void drifuzz_handle(void *opaque) {
	DrifuzzState *s = opaque;
	switch (read_mem(s->memory, 0x8, 0x8))
	{
	case CONST_DMA_INIT:
		dma_used = 1;
		((DMAAction *)s->actions)[s->actions_count++] = (DMAAction){
			.dma = read_mem(s->memory, 0x10, 0x8),
			.phy = read_mem(s->memory, 0x18, 0x8),
			.size = read_mem(s->memory, 0x20, 0x8),
			.alloc = 1,
			.consistent = 1
		};
		handle_dma_init(opaque, 
				read_mem(s->memory, 0x10, 0x8),
				read_mem(s->memory, 0x18, 0x8),
				read_mem(s->memory, 0x20, 0x8), 1);
		break;
	case CONST_DMA_EXIT:
		dma_used = 1;
		((DMAAction *)s->actions)[s->actions_count++] = (DMAAction){
			.dma = read_mem(s->memory, 0x10, 0x8),
			.phy = 0,
			.size = 0,
			.alloc = 0,
			.consistent = 1
		};
		handle_dma_exit(opaque,
				read_mem(s->memory, 0x10, 0x8), 1);
		break;
	case STREAM_DMA_INIT:
		dma_used = 1;
		((DMAAction *)s->actions)[s->actions_count++] = (DMAAction){
			.dma = read_mem(s->memory, 0x10, 0x8),
			.phy = read_mem(s->memory, 0x18, 0x8),
			.size = read_mem(s->memory, 0x20, 0x8),
			.alloc = 1,
			.consistent = 0
		};
		handle_dma_init(opaque, 
				read_mem(s->memory, 0x10, 0x8),
				read_mem(s->memory, 0x18, 0x8),
				read_mem(s->memory, 0x20, 0x8), 0);
		break;
	case STREAM_DMA_EXIT:
		dma_used = 1;
		((DMAAction *)s->actions)[s->actions_count++] = (DMAAction){
			.dma = read_mem(s->memory, 0x10, 0x8),
			.phy = 0,
			.size = 0,
			.alloc = 0,
			.consistent = 0
		};
		handle_dma_exit(opaque,
				read_mem(s->memory, 0x10, 0x8), 0);
		break;
    case EXEC_INIT:
		drifuzz_device_reset();
        handle_exec_init();
        break;
    case EXEC_EXIT:
        handle_exec_exit();
        break;
    case SUBMIT_STAGE:
        handle_submit_stage(read_mem(s->memory, 0x10, 0x8));
        break;
	case SUBMIT_KCOV_TRACE:
		handle_submit_kcov_trace(read_mem(s->memory, 0x10, 0x8),
				read_mem(s->memory, 0x18, 0x8));
		break;
	case KASAN:
		handle_guest_kasan();
		break;
	case REQ_RESET:
		handle_req_reset();
		break;
	case EXEC_TIMEOUT:
		handle_exec_timeout();
		break;
	default:
		printf("Unknown command %ld\n", read_mem(s->memory, 0x8, 0x8));
		break;
	}
}

static uint64_t __drifuzz_mmio_read(void *opaque, hwaddr addr,
                              unsigned size) {
	DrifuzzState *s = opaque;
	return read_mem(s->memory, addr, size);
}
static uint64_t drifuzz_mmio_read(void *opaque, hwaddr addr,
                              unsigned size) {

    DrifuzzState *s = opaque;

    (void)s;
    return __drifuzz_mmio_read(opaque, addr, size);
}

static void drifuzz_mmio_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size) {
    DrifuzzState *s = opaque;
	write_mem(s->memory, addr, val, size);
	if (addr == 0) {
		drifuzz_handle(opaque);
	}
    (void)s;
}
static const MemoryRegionOps drifuzz_mmio_ops = {
    .read = drifuzz_mmio_read,
    .write = drifuzz_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void drifuzz_pre_save(void *opaque) {
	DrifuzzState *s = opaque;
	/* stop if in fuzz mode */
	if (s->bitmap_file)
		return;
	s->input_index_save = input_index;
	printf("\nSaving input_index %lx\n", input_index);
}

static int drifuzz_post_load(void *opaque, int version_id) {
	DrifuzzState *s = opaque;
	/* stop if in fuzz mode */
	if (s->bitmap_file) {
		drifuzz_reset_memory_region();
		return 0;
	}
	input_index = s->input_index_save;
	printf("\nLoaded input_index %lx\n", input_index);
	drifuzz_loaded = 1;

	// Restore dma if we start from snapshot
	if (!dma_used) {
		for (int i = 0; i < s->actions_count; i++) {
			DMAAction a = ((DMAAction *)s->actions)[i];
			if (a.alloc)
				handle_dma_init(opaque, a.dma, a.phy, a.size, a.consistent);
			else
				handle_dma_exit(opaque, a.dma, a.consistent);
		}
	}

	return 0;
}

static const VMStateDescription vmstate = {
    .name = "drifuzz",
    .pre_save = drifuzz_pre_save,
    .post_load = drifuzz_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, DrifuzzState),
		VMSTATE_UINT64(input_index_save, DrifuzzState),
		VMSTATE_UINT8_ARRAY(actions, DrifuzzState, sizeof(DMAAction)*0x1000),
		VMSTATE_UINT64(actions_count, DrifuzzState),
	    VMSTATE_END_OF_LIST()
	}
};

static void drifuzz_class_init(ObjectClass *klass, void *data) {
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

	k->realize = pci_drifuzz_realize;
	k->vendor_id = 0x7777;
	k->device_id = 0x7777;
	k->subsystem_vendor_id = 0x7777;
	k->subsystem_id = 0x7777;
	k->revision = 0;
	k->class_id = PCI_CLASS_COMMUNICATION_SERIAL;
	set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

	dc->props = drifuzz_properties;
	dc->vmsd = &vmstate;
}

static void pci_drifuzz_realize(PCIDevice *pci_dev, Error **errp) {
	DrifuzzState *d = DRIFUZZ(pci_dev);

    memory_region_init_io(&d->mmio, OBJECT(d), &drifuzz_mmio_ops, d,
                          "drifuzz-mmio", 0x10000);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

	drifuzz_setup_socket(d->socket_path);
	drifuzz_open_bitmap(d->bitmap_file, d->bitmap_size);
	drifuzz_set_timeout(d->timeout_sec);

	const uint64_t info_start = 0x40;
	char *ind = d->memory + info_start;

	if (!d->target_name)
		d->target_name = (char*)"";
	uint64_t *target_size = (uint64_t*) ind;
	*target_size = strlen(d->target_name);
	ind += sizeof(uint64_t);
	memcpy(ind, d->target_name, strlen(d->target_name));
	ind += strlen(d->target_name);

	if (!d->prog_name)
		d->prog_name = (char*)"";
	target_size = (uint64_t*) ind;
	*target_size = strlen(d->prog_name);
	ind += sizeof(uint64_t);
	memcpy(ind, d->prog_name, strlen(d->prog_name));
	ind += strlen(d->prog_name);

	d->actions_count = 0;
	memset(d->actions, 0, sizeof(d->actions));

}

static void drifuzz_instance_init(Object *obj) {
	
}

static const TypeInfo drifuzz_info = {
	.name          = "drifuzz",
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(DrifuzzState),
	.instance_init = drifuzz_instance_init,
	.class_size    = sizeof(DrifuzzClass),
	.abstract      = false,
	.class_init    = drifuzz_class_init,
	.instance_init = drifuzz_instance_init,
};

static void drifuzz_register_types(void) {
	printf("Entering drifuzz_register_types\n");
	type_register_static(&drifuzz_info);
	printf("Leaving drifuzz_register_types\n");
}

type_init(drifuzz_register_types)

void drifuzz_reg_hw_ops(const struct drifuzz_hw_ops *ops) {
	drifuzz_device_reset = ops->reset;
}
