#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "qom/object.h"
#include "sysemu/dma.h"
#include "kcov-trace.h"

#define PAGE_SIZE 0x1000

struct trace_page {
    uint64_t phy_page;
    struct trace_page *next;
};

struct trace_page *head = NULL;
struct trace_page *tail = NULL;
size_t size = 0;

void *trace = NULL;
                            
void register_trace_page(uint64_t page) {

    struct trace_page *npage = NULL; 
    npage = malloc(sizeof(struct trace_page));
    /* init */
    npage->phy_page = page;
    npage->next = NULL;

    if (head == NULL) {
        head = npage;
        tail = npage;
    }
    else {
        tail->next = npage;
        tail = npage;
    }
    size += PAGE_SIZE;
}

void copy_trace_from_guest (uint8_t *bitmap) {

    struct trace_page *p = head;

    if (!head) {
        printf("No trace page registered\n");
        return;
    }

    for(uint64_t offset = 0; offset < size && p; offset += PAGE_SIZE) {
        cpu_physical_memory_read((uint32_t)p->phy_page, bitmap + offset,
                PAGE_SIZE);
        p = p->next;
    }

    int count = 0;
    for(int i = 0; i < size; i++)
        if (bitmap[i] != 255) 
            count ++;
    
    printf("QEMU: bitmap cover %d bytes\n", count);
}