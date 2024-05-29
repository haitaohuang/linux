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

/* Pages, which are being tracked by the page reclaimer. */
#define SGX_EPC_PAGE_RECLAIMER_TRACKED	BIT(0)

/* Pages on free list */
#define SGX_EPC_PAGE_IS_FREE		BIT(1)

/**
 * enum sgx_reclaim - Whether EPC reclamation is allowed within a function.
 * %SGX_NO_RECLAIM:		Do not reclaim EPC pages.
 * %SGX_DO_RECLAIM:		Reclaim EPC pages as needed.
 */
enum sgx_reclaim {
	SGX_NO_RECLAIM,
	SGX_DO_RECLAIM
};

struct sgx_cgroup;

struct sgx_epc_page {
	unsigned int section;
	u16 flags;
	u16 poison;
	struct sgx_encl_page *owner;
	struct list_head list;
#ifdef CONFIG_CGROUP_MISC
	struct sgx_cgroup *sgx_cg;
#endif
};

static inline void sgx_epc_page_set_cgroup(struct sgx_epc_page *page, struct sgx_cgroup *cg)
{
#ifdef CONFIG_CGROUP_MISC
	page->sgx_cg = cg;
#endif
}

static inline struct sgx_cgroup *sgx_epc_page_get_cgroup(struct sgx_epc_page *page)
{
#ifdef CONFIG_CGROUP_MISC
	return page->sgx_cg;
#else
	return NULL;
#endif
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

void sgx_free_epc_page(struct sgx_epc_page *page);

void sgx_reclaim_direct(void);
void sgx_mark_page_reclaimable(struct sgx_epc_page *page);
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page);
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, enum sgx_reclaim reclaim);

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
