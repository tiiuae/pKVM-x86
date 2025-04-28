// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#include <pkvm.h>
#include "ept.h"
#include "coredump.h"

int pkvm_prepare_vm_coredump(struct mm_struct *mm)
{
       struct pkvm_shadow_vm *vm;

       vm = get_shadow_vm_by_mm(mm);
       if (!vm)
               return -ENOENT;

       pkvm_pgstate_pgt_deinit(vm);
       return 0;
}

