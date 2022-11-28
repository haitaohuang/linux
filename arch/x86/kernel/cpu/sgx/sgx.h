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
#define SGX_NR_TO_SCAN			16
#define SGX_NR_LOW_PAGES		32
#define SGX_NR_HIGH_PAGES		64

/* Pages, which are not tracked by the page reclaimer. */
#define SGX_EPC_PAGE_RECLAIMER_UNTRACKED 0

/* Pages, which are being tracked by the page reclaimer. */
#define SGX_EPC_PAGE_RECLAIMER_TRACKED	BIT(0)

/* Pages on free list */
#define SGX_EPC_PAGE_IS_FREE		BIT(1)
/* Pages allocated for KVM guest */
#define SGX_EPC_PAGE_KVM_GUEST		BIT(2)
/* page flag to indicate reclaim is in progress */
#define SGX_EPC_PAGE_RECLAIM_IN_PROGRESS BIT(3)
/* flag for SECS or normal EPC pages */
#define SGX_EPC_PAGE_ENCLAVE		BIT(4)
/* flag for pages used for Version Array (VA) */
#define SGX_EPC_PAGE_VERSION_ARRAY	BIT(5)

struct sgx_epc_cgroup;

struct sgx_epc_page {
	unsigned int section;
	u16 flags;
	u16 poison;
	union {
		struct sgx_encl_page *encl_owner;
		/* Use when SGX_EPC_PAGE_KVM_GUEST set in ->flags: */
		void __user *vepc_vaddr;
		struct sgx_encl *encl;
	};
	struct list_head list;
	struct sgx_epc_cgroup *epc_cg;
};

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
 * This data structure wraps a list of reclaimable EPC pages, and a list of
 * non-reclaimable EPC pages and is used to implement a LRU policy during
 * reclamation.
 */
struct sgx_epc_lru_lists {
	spinlock_t lock;
	struct list_head reclaimable;
	struct list_head unreclaimable;
};

static inline void sgx_lru_init(struct sgx_epc_lru_lists *lrus)
{
	spin_lock_init(&lrus->lock);
	INIT_LIST_HEAD(&lrus->reclaimable);
	INIT_LIST_HEAD(&lrus->unreclaimable);
}

/*
 * Must be called with queue lock acquired
 */
static inline void sgx_lru_push(struct list_head *list, struct sgx_epc_page *page)
{
	list_add_tail(&page->list, list);
}

/*
 * Must be called with queue lock acquired
 */
static inline struct sgx_epc_page * sgx_lru_pop(struct list_head *list)
{
	struct sgx_epc_page *epc_page;

	if (list_empty(list))
		return NULL;

	epc_page = list_first_entry(list, struct sgx_epc_page, list);
	list_del_init(&epc_page->list);
	return epc_page;
}

/*
 * Must be called with queue lock acquired
 */
static inline struct sgx_epc_page * sgx_lru_peek(struct list_head *list)
{
	return list_first_entry_or_null(list, struct sgx_epc_page, list);
}

struct sgx_epc_page *__sgx_alloc_epc_page(void);
void sgx_free_epc_page(struct sgx_epc_page *page);

void sgx_reclaim_direct(void);
void sgx_record_epc_page(struct sgx_epc_page *page, unsigned long flags);
int sgx_drop_epc_page(struct sgx_epc_page *page);
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim);
int sgx_reclaim_epc_pages(int nr_to_scan, bool ignore_age,
			  struct sgx_epc_cgroup *epc_cg);
void sgx_isolate_epc_pages(struct sgx_epc_lru_lists *lrus, int *nr_to_scan,
			   struct list_head *dst);
bool sgx_epc_oom(struct sgx_epc_lru_lists *lrus);

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
