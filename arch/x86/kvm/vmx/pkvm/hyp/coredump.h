// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#include <linux/mm_types.h>
#include <linux/errno.h>

#ifdef CONFIG_PKVM_INTEL_PROTECTED_VM_COREDUMP
int pkvm_prepare_vm_coredump(struct mm_struct *mm);
#else
int pkvm_prepare_vm_coredump(struct mm_struct *mm)
{
       return -ENOTSUPP;
}
#endif
