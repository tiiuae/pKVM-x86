// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#include <pkvm.h>
#include <capabilities.h>
#include <mmu.h>
#include <mmu/spte.h>

#include "pkvm_hyp.h"
#include "pgtable.h"

#include "ve_emulation.h"

static inline bool is_ve_suppressed(u64 spte)
{
	return !!(spte & SUPPRESS_VE);
}

static inline bool is_ept_violation_convertible(u64 spte, int level)
{
	/* The EPT violation is convertible IF VE is not suppressed AND either
	 * of the following conditions hold:
	 * 1. The entry is not present (bits [2:0] = 0).
	 * 2. The entry is present (bits [2:0] != 0) and maps to a page
	 *    (i.e. level = 4k page or bit 7 = 1 for large page). The access
	 *    caused EPT violation.
	 */
	return !is_ve_suppressed(spte) &&
		(!(spte & VMX_EPT_RWX_MASK) || is_last_spte(spte, level));
}

static int pkvm_fill_ve_info(struct shadow_vcpu_state *shadow_vcpu,
			     u64 exit_qualification)
{
	if (!(vmcs_readl(GUEST_CR0) & X86_CR0_PE)) {
		/* Protection Enable not set */
		return 1;
	}

	if (shadow_vcpu_is_ve_valid(shadow_vcpu)) {
		/* Previous #VE not handled, non-convertible EPT violation */
		return 1;
	}

	/* Fill it up */
	shadow_vcpu->ve_info.exit_reason = EXIT_REASON_EPT_VIOLATION;
	shadow_vcpu->ve_info.exit_qual = exit_qualification;
	shadow_vcpu->ve_info.gla = vmcs_readl(GUEST_LINEAR_ADDRESS);
	shadow_vcpu->ve_info.gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	shadow_vcpu->ve_info.valid = EPT_VIOLATION_VE_VALID;

	return 0;
}

int pkvm_handle_ve_emulation(struct shadow_vcpu_state *shadow_vcpu,
			     u64 gpa,
			     u64 exit_qualification)
{
	struct pkvm_shadow_vm *vm = shadow_vcpu->vm;
	struct shadow_ept_desc *desc = &vm->sept_desc;
	struct pkvm_pgtable *sept = &desc->sept;
	struct pkvm_pgtable_ops *pgt_ops = sept->pgt_ops;
	unsigned long phys;
	u64 prot;
	int level;

	if (!vmx_has_ept_violation_ve_emulation()) {
		/* The VE emulation is not used */
		return -ENODEV;
	}

	/*
	 * The VE should be emulated. If the VE conditions are met, fill in the
	 * VE info.
	 */
	pkvm_pgtable_lookup(sept, gpa, &phys, &prot, &level);

	/* HACK: Would be better to use the raw PTE value */
	if (level != PG_LEVEL_4K) {
		pgt_ops->pgt_entry_mkhuge(&prot);
	}

	if (!is_ept_violation_convertible(prot, level)) {
		/* A non-convertible EPT violation */
		return -1;
	}

	return pkvm_fill_ve_info(shadow_vcpu, exit_qualification);
}

int pkvm_inject_ve(struct shadow_vcpu_state *shadow_vcpu,
		   u64 exit_qualification)
{
	u32 intr_info;

	if (WARN_ON_ONCE(!shadow_vcpu_is_ve_valid(shadow_vcpu))) {
		return -EINVAL;
	}

	/* FIXME: Should check bit 20 from VMCS exception bitmap */
	/* Fire it up */
	intr_info = VE_VECTOR | INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION;
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);

	return 0;
}

