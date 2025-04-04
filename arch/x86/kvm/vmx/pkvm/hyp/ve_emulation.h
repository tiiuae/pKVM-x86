// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#ifndef _PKVM_VE_EMULATION_H_
#define _PKVM_VE_EMULATION_H_

#include <linux/types.h>

struct shadow_vcpu_state;

#if IS_ENABLED(CONFIG_PKVM_INTEL_VE_EMULATION)
int pkvm_handle_ve_emulation(struct shadow_vcpu_state *shadow_vcpu,
                             u64 gpa,
                             u64 exit_qualification);
int pkvm_inject_ve(struct shadow_vcpu_state *shadow_vcpu,
                   u64 exit_qualification);
#else
static inline int pkvm_handle_ve_emulation(struct shadow_vcpu_state *shadow_vcpu,
                                           u64 gpa,
                                           u64 exit_qualification) { return -ENODEV; }
static inline int pkvm_inject_ve(struct shadow_vcpu_state *shadow_vcpu,
                                 u64 exit_qualification) { return -ENODEV; }
#endif
#endif /* _PKVM_VE_EMULATION_H_ */
