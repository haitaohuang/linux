/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_SGX_H
#define _X86_SGX_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/asm.h>
#include <asm/sgx.h>

#undef pr_fmt
#define pr_fmt(fmt) "sgx: " fmt

#define EREMOVE_ERROR_MESSAGE \
	"EREMOVE returned %d (0x%x) and an EPC page was leaked. SGX may become unusable. " \
	"Refer to Documentation/arch/x86/sgx.rst for more information."

#define SGX_MAX_EPC_SECTIONS		8
#define SGX_EEXTEND_BLOCK_SIZE		256

/*
 * Maximum number of pages to scan for reclaiming.
 */
#define SGX_NR_TO_SCAN_MAX		32U
#define SGX_NR_TO_SCAN			16
#define SGX_NR_LOW_PAGES		32
#define SGX_NR_HIGH_PAGES		64

enum sgx_epc_page_state {
	/*
	 * Allocated but not tracked by the reclaimer.
	 *
	 * Pages allocated for virtual EPC which are never tracked by the host
	 * reclaimer; pages just allocated from free list but not yet put in
	 * use; pages just reclaimed, but not yet returned to the free list.
	 * Becomes FREE after sgx_free_epc().
	 * Becomes RECLAIMABLE after sgx_mark_page_reclaimable().
	 */
	SGX_EPC_PAGE_NOT_TRACKED = 0,

	/*
	 * Page is in the free list, ready for allocation.
	 *
	 * Becomes NOT_TRACKED after sgx_alloc_epc_page().
	 */
	SGX_EPC_PAGE_FREE = 1,

	/*
	 * Page is in use and tracked in a reclaimable LRU list.
	 *
	 * Becomes NOT_TRACKED after sgx_unmark_page_reclaimable().
	 * Becomes RECLAIM_IN_PROGRESS in sgx_reclaim_pages() when identified
	 * for reclaiming.
	 */
	SGX_EPC_PAGE_RECLAIMABLE = 2,

	/*
	 * Page is in the middle of reclamation.
	 *
	 * Back to RECLAIMABLE if reclamation fails for any reason.
	 * Becomes NOT_TRACKED if reclaimed successfully.
	 */
	SGX_EPC_PAGE_RECLAIM_IN_PROGRESS = 3,
};

#define SGX_EPC_PAGE_STATE_MASK GENMASK(1, 0)

struct sgx_epc_cgroup;

struct sgx_epc_page {
	unsigned int section;
	u16 flags;
	u16 poison;
	struct sgx_encl_page *owner;
	struct list_head list;
	struct sgx_epc_cgroup *epc_cg;
};

static inline void sgx_epc_page_reset_state(struct sgx_epc_page *page)
{
	page->flags &= ~SGX_EPC_PAGE_STATE_MASK;
}

static inline void sgx_epc_page_set_state(struct sgx_epc_page *page, unsigned long flags)
{
	page->flags &= ~SGX_EPC_PAGE_STATE_MASK;
	page->flags |= (flags & SGX_EPC_PAGE_STATE_MASK);
}

static inline bool sgx_epc_page_reclaim_in_progress(unsigned long flags)
{
	return SGX_EPC_PAGE_RECLAIM_IN_PROGRESS == (flags & SGX_EPC_PAGE_STATE_MASK);
}

static inline bool sgx_epc_page_reclaimable(unsigned long flags)
{
	return SGX_EPC_PAGE_RECLAIMABLE == (flags & SGX_EPC_PAGE_STATE_MASK);
}

/*
 * Contains the tracking data for NUMA nodes having EPC pages. Most importantly,
 * the free page list local to the node is stored here.
 */
struct sgx_numa_node {
	struct list_head free_page_list;
	struct list_head sgx_poison_page_list;
	unsigned long size;
	spinlock_t lock;
};

/*
 * The firmware can define multiple chunks of EPC to the different areas of the
 * physical memory e.g. for memory areas of the each node. This structure is
 * used to store EPC pages for one EPC section and virtual memory area where
 * the pages have been mapped.
 */
struct sgx_epc_section {
	unsigned long phys_addr;
	void *virt_addr;
	struct sgx_epc_page *pages;
	struct sgx_numa_node *node;
};

extern struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

static inline unsigned long sgx_get_epc_phys_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = &sgx_epc_sections[page->section];
	unsigned long index;

	index = ((unsigned long)page - (unsigned long)section->pages) / sizeof(*page);

	return section->phys_addr + index * PAGE_SIZE;
}

static inline void *sgx_get_epc_virt_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = &sgx_epc_sections[page->section];
	unsigned long index;

	index = ((unsigned long)page - (unsigned long)section->pages) / sizeof(*page);

	return section->virt_addr + index * PAGE_SIZE;
}

/*
 * Contains EPC pages tracked by the global reclaimer (ksgxd) or an EPC
 * cgroup.
 */
struct sgx_epc_lru_list {
	spinlock_t lock;
	struct list_head reclaimable;
};

static inline void sgx_lru_init(struct sgx_epc_lru_list *lru)
{
	spin_lock_init(&lru->lock);
	INIT_LIST_HEAD(&lru->reclaimable);
}

struct sgx_epc_page *__sgx_alloc_epc_page(void);
void sgx_free_epc_page(struct sgx_epc_page *page);

void sgx_reclaim_direct(void);
void sgx_mark_page_reclaimable(struct sgx_epc_page *page);
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page);
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim);
unsigned int sgx_do_epc_reclamation(struct list_head *iso);
unsigned int sgx_isolate_epc_pages(struct sgx_epc_lru_list *lru, unsigned int nr_to_scan,
				   struct list_head *dst);

void sgx_ipi_cb(void *info);

#ifdef CONFIG_X86_SGX_KVM
int __init sgx_vepc_init(void);
#else
static inline int __init sgx_vepc_init(void)
{
	return -ENODEV;
}
#endif

void sgx_update_lepubkeyhash(u64 *lepubkeyhash);

#endif /* _X86_SGX_H */
