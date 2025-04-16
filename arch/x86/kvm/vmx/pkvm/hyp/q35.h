/*
 * SPDX-License-Identifier: GPL-2.0
 */
#include "pkvm_hyp.h"

/*
 * SMRAM regions
 */
#define SMRAM1_ADDR 0xa0000UL
#define SMRAM1_SZ 0x20000UL
#define SMRAM2_ADDR 0x80000000
#define SMRAM2_SZ 0x80000UL

/*
 * Regions to be fixed RO
 */
static const struct pkvm_share q35_guest_ro[] = {
	{ 0x0, 0x0 },
};

/*
 * Shared permanently, for now.
 */
#define LAPIC_DEFAULT_BASE 0xfee00000UL
#define LAPIC_SZ 0x1000UL
#define VRAM_ADDR 0xfd0000000UL
#define VRAM_SZ 0x1000000UL
#define PCI_CONFIG 0x7ffde000UL
#define PCI_CONFIG_SZ 0x1000UL

static const struct pkvm_share q35_dma_memmap[] = {
	{ LAPIC_DEFAULT_BASE, LAPIC_SZ },
	{ VRAM_ADDR, VRAM_SZ },
	{ PCI_CONFIG, PCI_CONFIG_SZ },
	{ 0, 0 },
};
