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


typedef struct AlxState_st {
	PCIDevice parent_obj;
	
	NICState *nic;
	NICConf conf;
	MemoryRegion mmio;
	MemoryRegion io;
    MemoryRegion msix;
} AlxState;

typedef struct AlxClass {
	PCIDeviceClass parent_class;
} AlxClass;

#define ALX(obj) \
	OBJECT_CHECK(AlxState, (obj), TYPE_PCI_DEVICE)

#define PCI_ALX(obj) \
	OBJECT_CHECK(PCIDevice, (obj), TYPE_PCI_DEVICE)

static uint32_t mmio_read_res = 0;
static uint32_t mmio_read_res_count = 0;

static void alx_class_init(ObjectClass *klass, void *data);
static void pci_alx_realize(PCIDevice *pci_dev, Error **errp);
static void alx_instance_init(Object *obj);
static void alx_register_types(void);

static size_t counter = 1; // For intr
static int idx = 0;        // for dma index

#define IRQ_FREQ 75
static void fire_interrupt(void* opaque, int i) {
	AlxState *s = ALX(opaque);
	PCIDevice *pci_dev = PCI_DEVICE(s);
	printf("fire interrupt\n");
	pci_set_irq(pci_dev, 1);
	if (msi_enabled(pci_dev)) {
		printf("fire msi interrupt\n");
		msi_notify(pci_dev, i);
	}
	if (msix_enabled(pci_dev)) {
		printf("fire msix interrupt\n");
		msix_notify(pci_dev, i);
	}
}

static void try_fire_interrupt(void* opaque) {
	if (counter++ % IRQ_FREQ == 0) {
		fire_interrupt(opaque, 0);
	}
}

static Property alx_properties[] = {
	DEFINE_NIC_PROPERTIES(AlxState, conf),
	DEFINE_PROP_END_OF_LIST(),
};

static void alx_device_reset(void) {
	counter = 1;
	idx = 0;
}

static const struct drifuzz_hw_ops alx_hw_ops = {
	.reset = alx_device_reset,
};

static uint64_t alx_mmio_read(void *opaque, hwaddr addr,
                              unsigned size) {

	uint64_t ret = 0;
    AlxState *s = opaque;
    (void)s;
    try_fire_interrupt(opaque);

	if (mmio_read_res_count > 0) {
		mmio_read_res_count--;
		ret = mmio_read_res;
	}
	else if (addr == 0x15E0 && size == 4) {
		ret = 0;
	}
	else if (addr == 0x15f6 && size == 2) {
		ret = get_data(1);
		// ret = communicate_read(1, addr, 1);
	}
    else {
		ret = get_data(size);
		// ret = communicate_read(1, addr, size);
	} 
	printf("mmio_read: %lx[%u] returns %lx\n", addr, size, ret);
	return ret;

}

static void alx_mmio_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size) {
    AlxState *s = opaque;
    try_fire_interrupt(opaque);
	if (val != 0)
		printf("mmio_write: %lx[%u] = %lx\n", addr, size, val);

	if (addr == 0x1414 && val == 0x7e10000) {
		mmio_read_res = 0x4;
		mmio_read_res_count = 2;
	}
	else if (addr == 0x1414 && val == 0x7f10000) {
		mmio_read_res = 0xa800;
		mmio_read_res_count = 2;
	}
	else if (addr == 0x15f2) {
		int v = communicate_read(3, 0, 4);
		if (v > 0xfff)
			fire_interrupt(opaque, 1);
	}
    (void)s;
	// communicate_write(1, addr, size, val);
}
static const MemoryRegionOps alx_mmio_ops = {
    .read = alx_mmio_read,
    .write = alx_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
	/*
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
	*/
};

static uint64_t alx_const_dma_read (void* opaque, hwaddr addr, unsigned size) {
	/* customization for alx */
    uint64_t ret = 0;
	if (addr == 0x1000) {
        ret = (1 << 16) | (idx << 20);
        idx ++;
    }
    else if (addr == 0x100c) {
        // ret = communicate_read(2, addr, size);
		ret = get_data(size);
        ret |= 0x80000000;
        ret &= ~(1 << 20);
        ret &= ~(1 << 30);
        ret &= ~(0xff00); // skb packet size (without these skb_over panic)
	}
	else {
		ret = get_data(size);
		// ret = communicate_read(2, addr, size);
	}
	return ret;
}

static void alx_const_dma_write(void*opaque, hwaddr addr, uint64_t val, 
		unsigned size) {
	// communicate_write(2, addr, size, val);
}

static const struct drifuzz_dma_ops alx_dma_ops = {
	.const_dma_read = alx_const_dma_read,
	.const_dma_write = alx_const_dma_write
};

static void alx_class_init(ObjectClass *klass, void *data) {
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

	k->realize = pci_alx_realize;
	k->vendor_id = 0x1969;
	k->device_id = 0x1091;
	k->subsystem_vendor_id = 0x1969;
	k->subsystem_id = 0x0091;
	k->revision = 0;
	k->class_id = PCI_CLASS_NETWORK_ETHERNET;
	set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);

	dc->props = alx_properties;
}

static int alx_add_pm_capability(PCIDevice *pdev) {
	/* offset 0 to auto mode */
	uint8_t offset = 0;
	 
	int ret = pci_add_capability(pdev, PCI_CAP_ID_PM, offset,
			PCI_PM_SIZEOF);
	return ret;
}

static int alx_init_msix(PCIDevice *pdev) {
	AlxState *d = ALX(pdev);
	/* More on magic numbers */
    int res = msix_init(PCI_DEVICE(d), 5,
                        &d->msix,
                        1, 0x0000, 
                        &d->msix,
                        1, 0x2000,
                        0xA0, NULL);
	for (int i = 0; i < 5; i++) {
		msix_vector_use(PCI_DEVICE(d), i);
	}
	return res;
}

static void pci_alx_realize(PCIDevice *pci_dev, Error **errp) {
    uint8_t *pci_conf;
	//DeviceState *dev = DEVICE(pci_dev);
	AlxState *d = ALX(pci_dev);
	/* Handle nic */
	qemu_macaddr_default_if_unset(&d->conf.macaddr);

	/* Handle interrupts */
	pci_conf = pci_dev->config;
	pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

	/* Handle memory regions */
    memory_region_init_io(&d->mmio, OBJECT(d), &alx_mmio_ops, d,
                          "alx-mmio", 0x10000);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

	memory_region_init(&d->msix, OBJECT(d), "alx-msix",
                       0x10000);
    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->msix);

	/* Handle capabilities */
	if (alx_add_pm_capability(pci_dev) < 0) {
		hw_error("Failed to initialize PM capability");
	}

	if (alx_init_msix(pci_dev) < 0) {
		hw_error("Failed to initialize MSIX");
	}

	drifuzz_reg_dma_ops(&alx_dma_ops);
	drifuzz_reg_hw_ops(&alx_hw_ops);
}

static void alx_instance_init(Object *obj) {
	AlxState *n = ALX(obj);
	device_add_bootindex_property(obj, &n->conf.bootindex,
					"bootindex", "ethernet-phy@0",
					DEVICE(n), NULL);
}

static const TypeInfo alx_info = {
	.name          = "alx",
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(AlxState),
	.instance_init = alx_instance_init,
	.class_size    = sizeof(AlxClass),
	.abstract      = false,
	.class_init    = alx_class_init,
	.instance_init = alx_instance_init,
};

static void alx_register_types(void) {
	type_register_static(&alx_info);
}

type_init(alx_register_types)
