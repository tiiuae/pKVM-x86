/*
 * SPDX-License-Identifier: GPL-2.0
 */
#include <pkvm.h>
#include <asm/apicdef.h>
#include <asm/pkvm.h>
#include <asm/pgtable_types.h>
#include <capabilities.h>
#include <vmx/vmx_debug.h>
#include <linux/ramlog.h>
#include <linux/types.h>
#include <linux/pagewalk.h>
#include "pkvm_hyp.h"
#include "nested.h"
#include "cpu.h"
#include "ept.h"
#include "debug.h"
#include "mem_protect.h"

#define PAGE_PRESENT_MASK	0x1ULL
#define PAGE_HUGE_MASK		0x80ULL
#define PAGE_SIZE_MASK		0x0000000000000FFFULL
#define PAGE_SIZE_2MB_MASK	0x00000000001FFFFFULL
#define PAGE_SIZE_1GB_MASK	0x000000003FFFFFFFULL
#define PAGE_PFN_MASK		0x000FFFFFFFFFF000ULL
#define PAGE_PFN_MASK_2MB	0x000FFFFFFFE00000ULL
#define PAGE_PFN_MASK_1GB	0x000FFFFFC0000000ULL

#define EPT_ENTRY_READ_MASK	(1ULL << 0)
#define EPT_ENTRY_WRITE_MASK	(1ULL << 1)
#define EPT_ENTRY_EXECUTE_MASK	(1ULL << 2)
#define EPT_ENTRY_LARGE_PAGE_MASK (1ULL << 7)
#define EPTP_PHYS_ADDR_WIDTH_MASK  0x7ULL
#define EPTP_PHYS_ADDR_WIDTH_48BIT 0x6ULL
#define SHADOW_VCPU_ARRAY(vm) \
        ((struct shadow_vcpu_array *)((void *)(vm) + sizeof(struct pkvm_shadow_vm)))

extern u64 __read_mostly shadow_mmio_value;
extern u64 __read_mostly shadow_mmio_mask;
extern pkvm_spinlock_t _host_ept_lock;

static u64 read_guest_phys(struct kvm_vcpu *vcpu, u64 phys, int stage)
{
	u64 vir, val;

	/*
	 * For the host VCPUs and guest stage 2 walks, use the host
	 * vaddrs. For the guest stage 1, translate to userspace.
	 */
	if ((vcpu->kvm->arch.pkvm.shadow_vm_handle == PKVM_HOST_HANDLE) ||
	    (stage == 1)) {
		vir = (u64)pkvm_phys_to_virt(phys);
		if (vir == ~0)
			return vir;
		return *(u64 *)vir;
	}

	vir = gfn_to_hva(vcpu->kvm, phys >> PAGE_SHIFT);
	if (kvm_is_error_hva(vir))
		return ~0;

	__get_user_hyp64(vcpu, &val, (u64 *)vir);
	return val;
}

static inline bool is_mmio_spte(u64 spte)
{
	return (spte & shadow_mmio_mask) == shadow_mmio_value;
}

#ifdef CONFIG_PKVM_INTEL_VMXROOT_MMIO

#include "q35.h"

static void __hyp_write_cr3(u64 cr3)
{
	asm volatile("mov %0,%%cr3": : "r" (cr3) : "memory");
}

static unsigned long __hyp_read_cr3(void)
{
	unsigned long cr3;

	asm volatile("mov %%cr3, %0" : "=r" (cr3));
	return cr3;
}

bool in_hyp_mode(void)
{
	if (__hyp_read_cr3() == pkvm_hyp->mmu->root_pa)
		return true;
	return false;
}

void init_guest_smm_dma(void *ptr)
{
	struct pkvm_shadow_vm *vm = ptr;

	mmget(current->mm);
	vm->mm = current->mm;
	memcpy(&vm->shares, &q35_dma_memmap, sizeof(q35_dma_memmap));
}

int check_donation_whitelist(u64 addr, size_t size)
{
	int i = 0;

	while (q35_dma_memmap[i].size != 0x0) {
		if ((addr >= q35_dma_memmap[i].gpa) &&
		   ((addr + size - 1) < (q35_dma_memmap[i].gpa +
					 q35_dma_memmap[i].size)))
			return 1;
		i++;
	}
	return 0;
}

int is_guest_ro(u64 addr, size_t size)
{
	int i = 0;

	while (q35_guest_ro[i].size != 0x0) {
                if ((addr >= q35_guest_ro[i].gpa) &&
                   ((addr + size - 1) < (q35_guest_ro[i].gpa +
					 q35_guest_ro[i].size)))
                        return 1;
                i++;
        }
	return 0;
}

unsigned long guest_virt_to_phys(struct kvm_vcpu *vcpu, u64 cr3, u64 virt_addr, u64 *ptep, int *l)
{
	u64 pml4i = (virt_addr >> 39) & 0x1FF;
	u64 pdpti = (virt_addr >> 30) & 0x1FF;
	u64 pdi   = (virt_addr >> 21) & 0x1FF;
	u64 pti   = (virt_addr >> 12) & 0x1FF;
	u64 pml4e, pdpte, pde, pte;

	/*
	 * We support only 64bit 4 level walks, for now. See the capabilities.h
	 */
	if (*l)
		*l = 4;
	pml4e = read_guest_phys(vcpu, (cr3 & PAGE_PFN_MASK) + pml4i * sizeof(u64), 0);
	*ptep = pml4e;
	if ((pml4e == ~0) || !(pml4e & PAGE_PRESENT_MASK))
		return ~0;

	if (*l)
		*l= 3;
	pdpte = read_guest_phys(vcpu, (pml4e & PAGE_PFN_MASK) + pdpti * sizeof(u64), 0);
	*ptep = pdpte;
	if ((pdpte == ~0) || !(pdpte & PAGE_PRESENT_MASK))
		return ~0;
	if (pdpte & PAGE_HUGE_MASK)
		return ((pdpte & PAGE_PFN_MASK_1GB) + (virt_addr & PAGE_SIZE_1GB_MASK));

	if (*l)
		*l = 2;
	pde = read_guest_phys(vcpu, (pdpte & PAGE_PFN_MASK) + pdi * sizeof(u64), 0);
	*ptep = pde;
	if ((pde == ~0) || !(pde & PAGE_PRESENT_MASK))
		return ~0;
	if (pde & PAGE_HUGE_MASK)
		return ((pde & PAGE_PFN_MASK_2MB) + (virt_addr & PAGE_SIZE_2MB_MASK));

	if (*l)
		*l = 1;
	pte = read_guest_phys(vcpu, (pde & PAGE_PFN_MASK) + pti * sizeof(u64), 0);
	*ptep = pte;
	if ((pte == ~0) || !(pte & PAGE_PRESENT_MASK))
		return ~0;

	return (pte & PAGE_PFN_MASK) + (virt_addr & PAGE_SIZE_MASK);
}

static unsigned long virt_to_phys_user(struct mm_struct *mm, unsigned long virt)
{
	struct vm_area_struct *vma;
	struct folio_walk fw;
	struct folio *folio;

	phys_addr_t phys = ~0;

	down_read(&mm->mmap_lock);
	vma = find_vma(mm, virt);
	if (!vma || virt < vma->vm_start)
		goto out;

	folio = folio_walk_start(&fw, vma, virt, 0);
	if (folio && fw.page) {
		phys = page_to_phys(fw.page);
	}
	folio_walk_end(&fw, vma);
out:
	up_read(&mm->mmap_lock);
	return phys;
}

unsigned long pkvm_user_to_phys(struct kvm_vcpu *vcpu, unsigned long vaddr)
{
	struct shadow_vcpu_state *shadow_vcpu;
	unsigned long phys;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();
	phys = guest_virt_to_phys(vcpu, shadow_vcpu->vm->mm->pgd->pgd, vaddr, NULL, NULL);

	put_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);

	return phys;
}

int __get_user_hyp64(struct kvm_vcpu *vcpu, u64 *ret, u64 *vaddr)
{
	struct shadow_vcpu_state *shadow_vcpu;
	u64 val;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	/* FIXME: why is our vmcs cr3 broken? */
	__hyp_write_cr3(pkvm_virt_to_phys(shadow_vcpu->vm->mm->pgd));
	asm volatile("stac" ::: "memory");
	val = *(u64 *)vaddr;
	asm volatile("clac" ::: "memory");
	__hyp_write_cr3(pkvm_hyp->mmu->root_pa);

	*ret = val;

	put_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);

	return 0;
}

static int hyp_check_owner(struct shadow_vcpu_state *shadow_vcpu, unsigned long addr, int len)
{
	unsigned long phys;
	int id;

	if (pkvm_is_share(shadow_vcpu->vm, addr, len))
		return 0;

	phys = virt_to_phys_user(shadow_vcpu->vm->mm, addr);
	if (phys == ~0)
		return -EINVAL;

	id = pkvm_page_owner(phys);
	if (id != to_shadow_vm_handle(shadow_vcpu->shadow_vcpu_handle))
		panic("illegal guest read or write\n");

	return 0;
}

/*
 * Before acting on a page, verify the page owner. Each vm can only
 * manipulate its own by using the hyp mode.
 */
int __hyp_read_guest_page(struct kvm_vcpu *vcpu, struct kvm_memory_slot *slot,
			  gfn_t gfn, void *data, int offset, int len)
{
	struct shadow_vcpu_state *shadow_vcpu;
	unsigned long addr;
	int res;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;

	addr += offset;
	res = hyp_check_owner(shadow_vcpu, addr, len);
	if (res)
		return -EFAULT;

	__hyp_write_cr3(pkvm_virt_to_phys(shadow_vcpu->vm->mm->pgd));
	asm volatile("stac" ::: "memory");
	while (len--)
		*(u8 *)data++ = *(u8 *)addr++;
	asm volatile("clac" ::: "memory");
	__hyp_write_cr3(pkvm_hyp->mmu->root_pa);

	put_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);

	return 0;
}

int __hyp_vcpu_write_guest_page(struct kvm_vcpu *vcpu,
				struct kvm_memory_slot *slot, gfn_t gfn,
				const void *data, int offset, int len)
{
	struct shadow_vcpu_state *shadow_vcpu;
	unsigned long addr;
	int res;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	addr = gfn_to_hva_memslot(slot, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;

	addr += offset;
	res = hyp_check_owner(shadow_vcpu, addr, len);
	if (res)
		return -EFAULT;

	__hyp_write_cr3(pkvm_virt_to_phys(shadow_vcpu->vm->mm->pgd));
	asm volatile("stac" ::: "memory");
	while (len--)
		*(u8 *)addr++ = *(u8 *)data++;
	asm volatile("clac" ::: "memory");
	__hyp_write_cr3(pkvm_hyp->mmu->root_pa);

	mark_page_dirty_in_slot(vcpu->kvm, slot, gfn);

	put_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);

	return 0;
}
#endif

/* KISS, minimal dependencies version of the EPT walk */

unsigned long guest_ept_lookup(struct kvm_vcpu *vcpu, u64 eptp, u64 gpa, u64 *spte, int *l)
{
	u64 pml4i = (gpa >> 39) & 0x1FF;
	u64 pdpti = (gpa >> 30) & 0x1FF;
	u64 pdi   = (gpa >> 21) & 0x1FF;
	u64 pti   = (gpa >> 12) & 0x1FF;
	u64 pml4e, pdpte, pde, pte, paw;

	paw = eptp & EPTP_PHYS_ADDR_WIDTH_MASK;
	if ((paw != 0) && (paw != EPTP_PHYS_ADDR_WIDTH_48BIT))
		BUG();

	if (l)
		*l = 4;
	pml4e = read_guest_phys(vcpu, (eptp & PAGE_PFN_MASK) + pml4i * sizeof(u64), 1);
	if (spte)
		*spte = pml4e;
	if ((pml4e == ~0) || !(pml4e & EPT_ENTRY_READ_MASK))
		return ~0;

	if (l)
		*l = 3;
	pdpte = read_guest_phys(vcpu, (pml4e & PAGE_PFN_MASK) + pdpti * sizeof(u64), 1);
	if (spte)
		*spte = pdpte;
	if ((pdpte == ~0) || !(pdpte & EPT_ENTRY_READ_MASK))
		return ~0;
	if (pdpte & EPT_ENTRY_LARGE_PAGE_MASK)
		return ((pdpte & PAGE_PFN_MASK_1GB) + (gpa & PAGE_SIZE_1GB_MASK));

	if (l)
		*l = 2;
	pde = read_guest_phys(vcpu, (pdpte & PAGE_PFN_MASK) + pdi * sizeof(u64), 1);
	if (spte)
		*spte = pde;
	if ((pde == ~0) || !(pde & EPT_ENTRY_READ_MASK))
		return ~0;
	if (pde & EPT_ENTRY_LARGE_PAGE_MASK)
		return ((pde & PAGE_PFN_MASK_2MB) + (gpa & PAGE_SIZE_2MB_MASK));

	if (l)
		*l = 1;
	pte = read_guest_phys(vcpu, (pde & PAGE_PFN_MASK) + pti * sizeof(u64), 1);
	if (spte)
		*spte = pte;
	if ((pte == ~0) || !(pte & EPT_ENTRY_READ_MASK))
		return ~0;
	return ((pte & PAGE_PFN_MASK) + (gpa & PAGE_SIZE_MASK));
}

/* The original pkvm walk. I prefer the for-dummies version above ^ */

unsigned long guest_pgt_lookup(struct kvm_vcpu *vcpu, unsigned long vaddr)
{
	struct shadow_vcpu_state *shadow_vcpu;
	struct pkvm_shadow_vm *vm;
	struct shadow_ept_desc *desc;
	struct pkvm_pgtable *sept;
	unsigned long phys;
	u64 gprot;
	int level;

	if (vaddr % PAGE_SIZE)
		return ~0;

	shadow_vcpu = get_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);
	if (!shadow_vcpu)
		BUG();

	vm = shadow_vcpu->vm;
	desc = &vm->sept_desc;
	sept = &desc->sept;

	pkvm_pgtable_lookup(sept, vaddr, &phys, &gprot, &level);

	put_shadow_vcpu(vcpu->pkvm_shadow_vcpu_handle);

	return phys;
}

/*
 * Temporary debugger extensions - not for code use
 */
static __maybe_unused int print_guest_maps_by_handle(int shadow_vm_handle)
{
	struct pkvm_shadow_vm *vm = get_shadow_vm(shadow_vm_handle);
	struct shadow_vcpu_ref *vcpu_ref;
	int m1, m2, m3;
	int ret = 0;

	if (!vm) {
		pkvm_err("No such vm 0x%x\n", shadow_vm_handle);
		return -ENOENT;
	}

	vcpu_ref = &SHADOW_VCPU_ARRAY(vm)->ref[0];
	if (!vcpu_ref || !vcpu_ref->vcpu) {
		pkvm_err("VM has no attached vcpus\n");
		ret = -EINVAL;
		goto out;
	}

	m1 = print_guest_maps(vcpu_ref->vcpu->gvcpu, d_s);
	m2 = print_guest_maps(vcpu_ref->vcpu->gvcpu, d_k);
	m3 = print_guest_maps(vcpu_ref->vcpu->gvcpu, d_p);
	pr_info("Total %d shadow, %d kvm and %d pgstate mappings\n", m1, m2, m3);

out:
	put_shadow_vm(vm->shadow_vm_handle);

	return ret;
}

int print_host_maps(void)
{
	return print_guest_maps(&pkvm_hyp->host_vm.host_vcpus[0]->vmx.vcpu, d_s);
}

static int __print_guest_maps(struct kvm_vcpu *vcpu, dtype_t table)
{
	struct kvm_memslots *slots = vcpu->kvm->memslots[0];
	struct kvm_memory_slot *slot;
	struct pkvm_shadow_vm *vm = NULL;
	u64 slot_start = ~0UL, slot_end = ~0UL;
	u64 eptp = 0, spte, tmp, va, ma, sz = 0, mmio, sve;
	int bkt, idx, cnt = 0, perms, l;
	bool c = false;

	if (vcpu->kvm->arch.pkvm.shadow_vm_handle != PKVM_HOST_HANDLE) {
		vm = get_shadow_vm(vcpu->kvm->arch.pkvm.shadow_vm_handle);
		if (!vm) {
			pkvm_err("No such vm 0x%x\n",
				 vcpu->kvm->arch.pkvm.shadow_vm_handle);
			return -ENOENT;
		}
	}

	switch (table) {
	case d_s:
		if (vcpu->kvm->arch.pkvm.shadow_vm_handle == PKVM_HOST_HANDLE)
			eptp = pkvm_hyp->host_vm.ept->root_pa;
		else
			eptp = vm->sept_desc.sept.root_pa;
		pkvm_info("VCPU 0x%llx EPTP 0x%llx shadow mappings:\n",
			 (u64)vcpu, eptp);
		break;
	case d_k:
		if (vcpu->arch.mmu) {
			eptp = vcpu->arch.mmu->root.hpa;
			pkvm_info("VCPU 0x%llx EPTP 0x%llx kvm mappings:\n",
				  (u64)vcpu, eptp);
		}
		break;
	case d_p:
		if (vm) {
			eptp = vm->pgstate_pgt.root_pa;
			pkvm_info("VCPU 0x%llx EPTP 0x%llx pgstate mappings:\n",
				  (u64)vcpu, eptp);
		}
		break;
	default:
		break;
	}

	if (vm) {
		put_shadow_vm(vm->shadow_vm_handle);
	}

	if (!eptp) {
		pkvm_err("VCPU 0x%llx ept not set\n", (u64)vcpu);
		return -EINVAL;
	}
	idx = srcu_read_lock(&vcpu->kvm->srcu);

	/*
	 * Note: on X86 the memslots do not describe the MMIO regions,
	 * so this should never report any. In order to get those this
	 * should scan kvm io bus's as well, aka kvm->buses[KVM_MMIO_BUS].
	 */
	kvm_for_each_memslot(slot, bkt, slots) {
		if (!slot->npages)
			continue;

		slot_start = slot->base_gfn << PAGE_SHIFT;
		slot_end = slot_start + (slot->npages * PAGE_SIZE);
		ma = ~0ULL; va = ~0; sz = 0; mmio = false; perms = 0;
		pr_info("Guest slot 0x%llx - 0x%llx\n", slot_start, slot_end - 1);

		while (slot_start < slot_end) {
			tmp = guest_ept_lookup(vcpu, eptp, slot_start, &spte, &l);
			/* Log regions that are mapped */
			if (tmp != ~0) {
				switch (l) {
				case 3:
				case 2:
				case 1:
					cnt += 1;
					sz += PAGE_SIZE;
					break;
				default:
					BUG();
					break;
				}
				/* Record mapping start */
				if (ma == ~0ULL) {
					ma = tmp;
					va = slot_start;
					if (is_mmio_spte(spte))
						mmio = true;
					else
						mmio = false;
					perms = spte & 0x7;
					sve = spte & SUPPRESS_VE;
					goto cont;
				}
				/*
				 * If anything changed, print it.
				 */
				if ((perms != (spte & 0x7)) ||
				    (mmio != is_mmio_spte(spte)) ||
				    (sve != (spte & SUPPRESS_VE))) {
					c = true;
					goto print;
				}
				goto cont;

			} else {
				/* TODO
				 * If this is the host, the page has migrated.
				 * We may want to show to whom.
				 */
				spte = 0x0;
			}
print:
			if (ma != ~0ULL) {
				/* If it changed and we needed to print a line, step back */
				if (c) {
					slot_start -= PAGE_SIZE;
					c = false;
				}
				pkvm_info("0x%016llx -> 0x%016llx %llu 0x%d %s %s\n",
					  va, ma, sz, perms, (sve) ? "SVE" : "VE",
					  (mmio) ? "MMIO" : "MEMORY" );
				ma = ~0ULL; va = ~0; sz = 0; mmio = false; sve = 0;
			}

cont:
			switch(l) {
			case 3:
			case 2:
			case 1:
				slot_start += PAGE_SIZE;
				break;
			default:
				pkvm_info("%s: unable to walk given region\n", __func__);
				slot_start = ULONG_MAX;
				break;
			}
		}
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return cnt;
}

int print_guest_maps(struct kvm_vcpu *vcpu, dtype_t dt)
{
	if (dt == d_a) {
		__print_guest_maps(vcpu, d_s);
		__print_guest_maps(vcpu, d_k);
		__print_guest_maps(vcpu, d_p);

		return 0;
	}
	return __print_guest_maps(vcpu, dt);
}
