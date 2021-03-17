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


typedef struct HwState_st {
	PCIDevice parent_obj;
	
	NICState *nic;
	NICConf conf;
	MemoryRegion mmio;
	MemoryRegion io;
    MemoryRegion msix;
} HwState;

typedef struct HwClass {
	PCIDeviceClass parent_class;
} HwClass;

#define HW(obj) \
	OBJECT_CHECK(HwState, (obj), TYPE_PCI_DEVICE)

#define PCI_HW(obj) \
	OBJECT_CHECK(PCIDevice, (obj), TYPE_PCI_DEVICE)

static void hw_class_init(ObjectClass *klass, void *data);
static void pci_hw_realize(PCIDevice *pci_dev, Error **errp);
static void hw_instance_init(Object *obj);
static void hw_register_types(void);

static size_t counter = 1; // For intr
static int idx = 0;        // for dma index

#define IRQ_FREQ 75
static void fire_interrupt(void* opaque, int i) {
	HwState *s = HW(opaque);
	PCIDevice *pci_dev = PCI_DEVICE(s);
	// printf("fire interrupt\n");
	// pci_set_irq(pci_dev, 1);
	// pci_set_irq(pci_dev, 0);
	// if (msi_enabled(pci_dev)) {
	// 	printf("fire msi interrupt\n");
	// 	msi_notify(pci_dev, i);
	// }
	// if (msix_enabled(pci_dev)) {
	// 	printf("fire msix interrupt\n");
	// 	msix_notify(pci_dev, i);
	// }
}

static void try_fire_interrupt(void* opaque) {
	if (counter++ % IRQ_FREQ == 0) {
		fire_interrupt(opaque, 0);
	}
}

static Property hw_properties[] = {
	DEFINE_NIC_PROPERTIES(HwState, conf),
	DEFINE_PROP_END_OF_LIST(),
};

static void hw_device_reset(void) {
	counter = 1;
	idx = 0;
}

static const struct drifuzz_hw_ops hw_hw_ops = {
	.reset = hw_device_reset,
};

static uint64_t hw_mmio_read(void *opaque, hwaddr addr,
                              unsigned size) {

	uint64_t ret = 0;
    HwState *s = opaque;
    (void)s;
    try_fire_interrupt(opaque);

	ret = communicate_read(1, addr, size);
	// printf("input index: %lx\n", input_index);
	// printf("mmio_read: %lx[%u] returns %lx\n", addr, size, ret);
	return ret;

}

static void hw_mmio_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size) {
    HwState *s = opaque;
    try_fire_interrupt(opaque);
	// if (val != 0)
	// 	printf("mmio_write: %lx[%u] = %lx\n", addr, size, val);
	// if (addr == 0x80004 && val == 0)
	// 	fire_interrupt(opaque, 0);
    (void)s;
	// communicate_write(1, addr, size, val);
}
static const MemoryRegionOps hw_mmio_ops = {
    .read = hw_mmio_read,
    .write = hw_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t hw_const_dma_read (void* opaque, hwaddr addr, unsigned size) {
	/* customization for alx */
    uint64_t ret = 0;

	ret = communicate_read(2, addr, size);

	// if (addr == 0xe54 && size == 2)
	// 	ret = 0xffc;
	
	return ret;
}

static void hw_const_dma_write(void*opaque, hwaddr addr, uint64_t val, 
		unsigned size) {
	// communicate_write(2, addr, size, val);
}

static void* hw_get_stream_dma(uint64_t size) {
	void *buf = communicate_dma_buffer(size);
	return buf;
}

static const struct drifuzz_dma_ops hw_dma_ops = {
	.const_dma_read = hw_const_dma_read,
	.const_dma_write = hw_const_dma_write,
	.get_stream_dma = hw_get_stream_dma,
};

static const VMStateDescription vmstate_hw = {
    .name = "ath10k",
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, HwState),
        VMSTATE_END_OF_LIST()
	}
};

static void hw_class_init(ObjectClass *klass, void *data) {
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

	k->realize = pci_hw_realize;
	k->vendor_id = 0x168c;
	k->device_id = 0x003e;
	// k->subsystem_vendor_id = 0x1a56;
	// k->subsystem_id = 0x1525;
	k->subsystem_vendor_id = 0x144d;
	k->subsystem_id = 0xc135;
	k->revision = 0;
	k->class_id = PCI_CLASS_NETWORK_ETHERNET;
	set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);

	dc->props = hw_properties;
    dc->vmsd = &vmstate_hw;
}

static int hw_add_pm_capability(PCIDevice *pdev) {
	/* offset 0 to auto mode */
	uint8_t offset = 0;
	 
	int ret = pci_add_capability(pdev, PCI_CAP_ID_PM, offset,
			PCI_PM_SIZEOF);
	return ret;
}
static int hw_init_msi(PCIDevice *pdev) {
	return msi_init(pdev, 0, 32, true, true,  NULL);
}

static int hw_init_msix(PCIDevice *pdev) {
	HwState *d = HW(pdev);
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

static void pci_hw_realize(PCIDevice *pci_dev, Error **errp) {
    uint8_t *pci_conf;
	//DeviceState *dev = DEVICE(pci_dev);
	HwState *d = HW(pci_dev);
	/* Handle nic */
	qemu_macaddr_default_if_unset(&d->conf.macaddr);

	/* Handle interrupts */
	pci_conf = pci_dev->config;
	pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

	/* Handle memory regions */
    memory_region_init_io(&d->mmio, OBJECT(d), &hw_mmio_ops, d,
                          "hw-mmio", 0x10000000);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

	memory_region_init(&d->msix, OBJECT(d), "hw-msix",
                       0x1000000);
    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->msix);

	/* Handle capabilities */
	if (hw_add_pm_capability(pci_dev) < 0) {
		hw_error("Failed to initialize PM capability");
	}

	if (hw_init_msi(pci_dev) < 0) {
		hw_error("Failed to initialize MSI");
	}

	drifuzz_reg_dma_ops(&hw_dma_ops);
	drifuzz_reg_hw_ops(&hw_hw_ops);
}

static void hw_instance_init(Object *obj) {
	HwState *n = HW(obj);
	device_add_bootindex_property(obj, &n->conf.bootindex,
					"bootindex", "ethernet-phy@0",
					DEVICE(n), NULL);
}

static const TypeInfo hw_info = {
	.name          = "ath10k_pci",
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(HwState),
	.instance_init = hw_instance_init,
	.class_size    = sizeof(HwClass),
	.abstract      = false,
	.class_init    = hw_class_init,
	.instance_init = hw_instance_init,
};

static void hw_register_types(void) {
	type_register_static(&hw_info);
}

type_init(hw_register_types)


