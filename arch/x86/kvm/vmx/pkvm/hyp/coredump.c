// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#include <pkvm.h>
#include "pkvm_hyp.h"
#include "mem_protect.h"
#include "coredump.h"

static int pkvm_coredump_pgt_free_leaf(struct pkvm_pgtable *pgt,
				      unsigned long vaddr,
				      int level,
				      void *ptep,
				      struct pgt_flush_data *flush_data,
				      void *arg)
{
	unsigned long phys = pgt->pgt_ops->pgt_entry_to_phys(ptep);
	unsigned long size = pgt->pgt_ops->pgt_level_to_size(level);
	struct pkvm_shadow_vm *vm = pgstate_pgt_to_shadow_vm(pgt);
	int ret = 0;

	if (!pgt->pgt_ops->pgt_entry_present(ptep))
		return 0;

	switch(vm->vm_type) {
	case KVM_X86_PKVM_PROTECTED_VM: {
		pgt->mm_ops->get_page(ptep);
		ret = __pkvm_host_undonate_guest(phys, pgt, vaddr, size);
		pgt->mm_ops->put_page(ptep);
		flush_data->flushtlb |= true;
		break;
	}
	case KVM_X86_DEFAULT_VM:
		/*  Host already can access guest pages */
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		pkvm_err("%s failed: ret %d vm_type %d phys 0x%lx GPA 0x%lx size 0x%lx\n",
			 __func__, ret, vm->vm_type, phys, vaddr, size);
	return ret;
}

int pkvm_prepare_vm_coredump(struct mm_struct *mm)
{
       struct pkvm_shadow_vm *vm;

       vm = get_shadow_vm_by_mm(mm);
       if (!vm)
               return -ENOENT;

       pkvm_spin_lock(&vm->lock);
       pkvm_pgtable_destroy(&vm->pgstate_pgt, pkvm_coredump_pgt_free_leaf);
       pkvm_spin_unlock(&vm->lock);

       put_shadow_vm(vm->shadow_vm_handle);

       return 0;
}

