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
	"Refer to Documentation/x86/sgx.rst for more information."

#define SGX_MAX_EPC_SECTIONS		8
#define SGX_EEXTEND_BLOCK_SIZE		256
#define SGX_NR_TO_SCAN			16
#define SGX_NR_LOW_PAGES		32
#define SGX_NR_HIGH_PAGES		64

enum sgx_epc_page_state {
	/* Not tracked by the reclaimer:
	 * Pages allocated for virtual EPC which are never tracked by the host
	 * reclaimer; pages just allocated from free list but not yet put in
	 * use; pages just reclaimed, but not yet returned to the free list.
	 * Becomes FREE after sgx_free_epc()
	 * Becomes RECLAIMABLE or UNRECLAIMABLE after sgx_record_epc()
	 */
	SGX_EPC_PAGE_NOT_TRACKED = 0,

	/* Page is in the free list, ready for allocation
	 * Becomes NOT_TRACKED after sgx_alloc_epc_page()
	 */
	SGX_EPC_PAGE_FREE = 1,

	/* Page is in use and tracked in a reclaimable LRU list
	 * Becomes NOT_TRACKED after sgx_drop_epc()
	 * Becomes RECLAIM_IN_PROGRESS in sgx_reclaim_pages() when identified
	 * for reclaiming
	 */
	SGX_EPC_PAGE_RECLAIMABLE = 2,

	/* Page is in use but tracked in an unreclaimable LRU list. These are
	 * only reclaimable when the whole enclave is OOM killed or the enclave
	 * is released, e.g., VA, SECS pages
	 * Becomes NOT_TRACKED after sgx_drop_epc()
	 */
	SGX_EPC_PAGE_UNRECLAIMABLE = 3,

	/* Page is being prepared for reclamation, tracked in a temporary
	 * isolated list by the reclaimer.
	 * Changes in sgx_reclaim_pages() back to RECLAIMABLE if preparation
	 * fails for any reason.
	 * Becomes NOT_TRACKED if reclaimed successfully in sgx_reclaim_pages()
	 * and immediately sgx_free_epc() is called to make it FREE.
	 */
	SGX_EPC_PAGE_RECLAIM_IN_PROGRESS = 4,
};

#define SGX_EPC_PAGE_STATE_MASK GENMASK(2, 0)

/* flag for pages owned by a sgx_encl_page */
#define SGX_EPC_OWNER_PAGE		BIT(3)

/* flag for pages owned by a sgx_encl struct */
#define SGX_EPC_OWNER_ENCL		BIT(4)

struct sgx_epc_page {
	unsigned int section;
	u16 flags;
	u16 poison;
	union {
		struct sgx_encl_page *encl_page;
		struct sgx_encl *encl;
	};
	struct list_head list;
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
	return SGX_EPC_PAGE_RECLAIM_IN_PROGRESS == (flags &
						    SGX_EPC_PAGE_STATE_MASK);
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
 * Contains EPC pages tracked by the reclaimer (ksgxd).
 */
struct sgx_epc_lru_lists {
	spinlock_t lock;
	struct list_head reclaimable;
	/*
	 * Tracks SECS, VA pages,etc., pages only freeable after all its
	 * dependent reclaimables are freed.
	 */
	struct list_head unreclaimable;
};

static inline void sgx_lru_init(struct sgx_epc_lru_lists *lrus)
{
	spin_lock_init(&lrus->lock);
	INIT_LIST_HEAD(&lrus->reclaimable);
	INIT_LIST_HEAD(&lrus->unreclaimable);
}

struct sgx_epc_page *__sgx_alloc_epc_page(void);
void sgx_free_epc_page(struct sgx_epc_page *page);

void sgx_reclaim_direct(void);
void sgx_record_epc_page(struct sgx_epc_page *page, unsigned long flags);
int sgx_drop_epc_page(struct sgx_epc_page *page);
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim);
bool sgx_epc_oom(struct sgx_epc_lru_lists *lrus);
size_t sgx_reclaim_epc_pages(size_t nr_to_scan, bool ignore_age);
void sgx_isolate_epc_pages(struct sgx_epc_lru_lists *lrus, size_t nr_to_scan,
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
