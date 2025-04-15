// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#include <asm/apicdef.h>
#include <linux/ramlog.h>

#include "cpu.h"
#include "memory.h"

#define APIC_BASE_PHYS_MASK GENMASK_ULL(get_max_physaddr_bits(), 12)

__attribute__((unused))
char *print_apicstate(void)
{
       u64 apicbase_p, apicbase_v;
       char *s;

       pkvm_rdmsrl(MSR_IA32_APICBASE, apicbase_p);
       apicbase_v = (u64)pkvm_iophys_to_virt(apicbase_p & APIC_BASE_PHYS_MASK);
       s = __rlogp();

       __ramlog("APIC_BASE             0x%llx -> 0x%llx\n", apicbase_p, apicbase_v);
       __ramlog("APIC_ID               0x%x\n", ioread32((void *)(apicbase_v + APIC_ID)));
       __ramlog("APIC_LVR              0x%x\n", ioread32((void *)(apicbase_v + APIC_LVR)));
       __ramlog("APIC_VERSION          0x%x\n", GET_APIC_VERSION(ioread32((void *)(apicbase_v + APIC_LVR))));
       __ramlog("APIC_XAPIC            0x%x\n", APIC_XAPIC(ioread32((void *)(apicbase_v + APIC_LVR))));
       __ramlog("APIC_X2APIC           0x%llx\n", apicbase_p & X2APIC_ENABLE);
       __ramlog("APIC_EXT_SPACE        0x%x\n", APIC_EXT_SPACE(ioread32((void *)(apicbase_v + APIC_LVR))));
       __ramlog("APIC_TASKPRI          0x%x\n", ioread32((void *)(apicbase_v + APIC_TASKPRI)));
       __ramlog("APIC_PROCPRI          0x%x\n", ioread32((void *)(apicbase_v + APIC_PROCPRI)));
       __ramlog("APIC_ISR              0x%x\n", ioread32((void *)(apicbase_v + APIC_ISR)));
       __ramlog("APIC_TMR              0x%x\n", ioread32((void *)(apicbase_v + APIC_TMR)));
       __ramlog("APIC_IRR              0x%x\n", ioread32((void *)(apicbase_v + APIC_IRR)));
       __ramlog("APIC_ESR              0x%x\n", ioread32((void *)(apicbase_v + APIC_ESR)));
       __ramlog("APIC_EFEAT            0x%x\n", ioread32((void *)(apicbase_v + APIC_EFEAT)));

       return s;
}

