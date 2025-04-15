/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_DEBUG_H
#define __KVM_X86_VMX_DEBUG_H

#ifdef CONFIG_DEBUG_KERNEL
char *debug_dump_vmcs(void);
char *debug_dump_vmx_msr_state(void);
#else
static inline void char *debug_dump_vmcs(void) { return NULL; }
static inline void char *debug_dump_vmx_msr_state(void) { return NULL; }
#endif

#endif /* __KVM_X86_VMX_DEBUG_H */
