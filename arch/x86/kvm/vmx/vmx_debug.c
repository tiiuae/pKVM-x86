// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Technology Innovation Institute
 */
#include <linux/kernel.h>
#include <linux/ramlog.h>

#include <linux/bug.h>
#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#include <asm/page.h>

#define ramlog_reg_unavail_1(_reg) \
	__ramlog(_reg " is not available\n")

#define ramlog_msr_1(_msr_str, _msr) \
	__ramlog("%-35s\t0x%016llx\n", _msr_str, debug_read_msr(_msr))
#define ramlog_msr(msr) ramlog_msr_1(#msr, msr)
#define ramlog_msr_if(_cond, _msr)			\
	do {						\
		if ((_cond)) {				\
			ramlog_msr_1(#_msr, _msr);	\
		} else {				\
			ramlog_reg_unavail_1(#_msr);	\
		}					\
	} while(0)

#define ramlog_vmcs_1(_reg_str, _reg) \
	__ramlog("%-35s\t0x%016llx\n", _reg_str, debug_read_vmcs(_reg))
#define ramlog_vmcs(reg) ramlog_vmcs_1(#reg, reg)
#define ramlog_vmcs_if(_cond, _reg)				\
	do {							\
		if ((_cond)) {					\
			ramlog_vmcs_1(#_reg, _reg);		\
		} else {					\
			ramlog_reg_unavail_1(#_reg);		\
		}						\
	} while(0)

u64 debug_read_msr(u32 msr)
{
	DECLARE_ARGS(val, low, high);
	int errc = 0;
	int *err = &errc;

	asm volatile("1:	rdmsr ; xor %[err],%[err]\n"
		     "2:\n"
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_RDMSR_SAFE, %[err])
		     : [err] "=r" (*err), EAX_EDX_RET(val, low, high)
		     : "c" (msr));
	if (*err)
		return ~0;
	else
		return EAX_EDX_VAL(val, low, high);
}

static u64 __vmcs_read(unsigned long field)
{
	unsigned long value;

	asm_goto_output("1: vmread %[field], %[output]\n\t"
			  "jna %l[do_fail]\n\t"
			  _ASM_EXTABLE(1b, %l[do_exception])
			  : [output] "=r" (value)
			  : [field] "r" (field)
			  : "cc"
			  : do_fail, do_exception);

	return value;

do_fail:
	__ramlog("vmread failed: field=0x%lx\n", field);
	return 0;

do_exception:
	__ramlog("vmread exception: field=0x%lx\n", field);
        return 0;
}

u64 debug_read_vmcs(u64 field)
{
	return __vmcs_read(field);
}

static int msr_true_ctls_avail(void)
{
	return !!(debug_read_msr(MSR_IA32_VMX_BASIC) & BIT_ULL(55));
}

static int msr_ctl2_avail(void)
{
	return !!(debug_read_msr(MSR_IA32_VMX_PROCBASED_CTLS) & BIT_ULL(63));
}

static int msr_ept_vpid_cap_avail(void)
{
	return msr_ctl2_avail() &&
		(debug_read_msr(MSR_IA32_VMX_PROCBASED_CTLS2) &
		 (BIT_ULL(33) | BIT_ULL(37)));
}

static int msr_vmfunc_avail(void)
{
	return msr_ctl2_avail() &&
		(debug_read_msr(MSR_IA32_VMX_PROCBASED_CTLS2) & BIT_ULL(45));
}

static int msr_ctl3_avail(void)
{
	return !!(debug_read_msr(MSR_IA32_VMX_PROCBASED_CTLS) & BIT_ULL(49));
}

static int vmcs_secondary_exec_ctl_enabled(void)
{
	return !!(debug_read_vmcs(CPU_BASED_VM_EXEC_CONTROL) & BIT(31));
}

static int vmcs_tertiary_exec_ctl_enabled(void)
{
	return !!(debug_read_vmcs(CPU_BASED_VM_EXEC_CONTROL) & BIT(17));
}

char *debug_dump_vmx_msr_state(void)
{
	char *s = __rlogp();

	ramlog_msr(MSR_IA32_VMX_BASIC);
	ramlog_msr(MSR_IA32_VMX_PINBASED_CTLS);
	ramlog_msr(MSR_IA32_VMX_PROCBASED_CTLS);
	ramlog_msr(MSR_IA32_VMX_EXIT_CTLS);
	ramlog_msr(MSR_IA32_VMX_ENTRY_CTLS);

	ramlog_msr_if(msr_true_ctls_avail(),
		      MSR_IA32_VMX_TRUE_PINBASED_CTLS);
	ramlog_msr_if(msr_true_ctls_avail(),
		      MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	ramlog_msr_if(msr_true_ctls_avail(),
		      MSR_IA32_VMX_TRUE_EXIT_CTLS);
	ramlog_msr_if(msr_true_ctls_avail(),
		      MSR_IA32_VMX_TRUE_ENTRY_CTLS);

	ramlog_msr(MSR_IA32_VMX_MISC);
	ramlog_msr(MSR_IA32_VMX_CR0_FIXED0);
	ramlog_msr(MSR_IA32_VMX_CR0_FIXED1);
	ramlog_msr(MSR_IA32_VMX_CR4_FIXED0);
	ramlog_msr(MSR_IA32_VMX_CR4_FIXED1);
	ramlog_msr(MSR_IA32_VMX_VMCS_ENUM);

	ramlog_msr_if(msr_ctl2_avail(), MSR_IA32_VMX_PROCBASED_CTLS2);
	ramlog_msr_if(msr_ept_vpid_cap_avail(), MSR_IA32_VMX_EPT_VPID_CAP);
	ramlog_msr_if(msr_vmfunc_avail(), MSR_IA32_VMX_VMFUNC);
	ramlog_msr_if(msr_ctl3_avail(), MSR_IA32_VMX_PROCBASED_CTLS3);

	return s;
}

char *debug_dump_vmcs(void)
{
	char *s = __rlogp();
	u64 cr4;

	asm("mov %%cr4,%0" : "=r"(cr4));
	if (!(cr4 & (1 << X86_CR4_VMXE_BIT))) {
		__ramlog("vmx not enabled\n");
		return s;
	}
	ramlog_vmcs(VIRTUAL_PROCESSOR_ID);
	ramlog_vmcs(VM_ENTRY_MSR_LOAD_ADDR);
	ramlog_vmcs(VM_ENTRY_MSR_LOAD_COUNT);
	ramlog_vmcs(VM_EXIT_MSR_STORE_ADDR);
	ramlog_vmcs(VM_EXIT_MSR_STORE_COUNT);
	ramlog_vmcs(VM_EXIT_MSR_LOAD_ADDR);
	ramlog_vmcs(VM_EXIT_MSR_LOAD_COUNT);
	ramlog_vmcs(EPT_POINTER);
	ramlog_vmcs(PIN_BASED_VM_EXEC_CONTROL);
	ramlog_vmcs(CPU_BASED_VM_EXEC_CONTROL);
	ramlog_vmcs(VM_ENTRY_CONTROLS);
	ramlog_vmcs(VM_EXIT_CONTROLS);
	ramlog_vmcs(GUEST_LINEAR_ADDRESS);
	ramlog_vmcs(GUEST_PHYSICAL_ADDRESS);
	ramlog_vmcs_if(vmcs_secondary_exec_ctl_enabled(), SECONDARY_VM_EXEC_CONTROL);
	ramlog_vmcs_if(vmcs_tertiary_exec_ctl_enabled(), TERTIARY_VM_EXEC_CONTROL);

	return s;
}

