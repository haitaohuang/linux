// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2022 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include "epc_cgroup.h"

#define SGX_EPC_RECLAIM_MIN_PAGES		16U

static struct workqueue_struct *sgx_epc_cg_wq;

static inline u64 sgx_epc_cgroup_page_counter_read(struct sgx_epc_cgroup *epc_cg)
{
	return atomic64_read(&epc_cg->cg->res[MISC_CG_RES_SGX_EPC].usage) / PAGE_SIZE;
}

static inline u64 sgx_epc_cgroup_max_pages(struct sgx_epc_cgroup *epc_cg)
{
	return READ_ONCE(epc_cg->cg->res[MISC_CG_RES_SGX_EPC].max) / PAGE_SIZE;
}

/*
 * Get the lower bound of limits of a cgroup and its ancestors.  Used in
 * sgx_epc_cgroup_reclaim_work_func() to determine if EPC usage of a cgroup is over its limit
 * or its ancestors' hence reclamation is needed.
 */
static inline u64 sgx_epc_cgroup_max_pages_to_root(struct sgx_epc_cgroup *epc_cg)
{
	struct misc_cg *i = epc_cg->cg;
	u64 m = U64_MAX;

	while (i) {
		m = min(m, READ_ONCE(i->res[MISC_CG_RES_SGX_EPC].max));
		i = misc_cg_parent(i);
	}

	return m / PAGE_SIZE;
}

static inline struct sgx_epc_cgroup *sgx_epc_cgroup_from_misc_cg(struct misc_cg *cg)
{
	return (struct sgx_epc_cgroup *)(cg->res[MISC_CG_RES_SGX_EPC].priv);
}

static inline bool sgx_epc_cgroup_disabled(void)
{
	return !cgroup_subsys_enabled(misc_cgrp_subsys);
}

/**
 * sgx_epc_cgroup_lru_empty() - check if a cgroup tree has no pages on its LRUs
 * @root:	root of the tree to check
 *
 * Return: %true if all cgroups under the specified root have empty LRU lists.
 * Used to avoid livelocks due to a cgroup having a non-zero charge count but
 * no pages on its LRUs, e.g. due to a dead enclave waiting to be released or
 * because all pages in the cgroup are unreclaimable.
 */
bool sgx_epc_cgroup_lru_empty(struct misc_cg *root)
{
	struct cgroup_subsys_state *css_root;
	struct cgroup_subsys_state *pos;
	struct sgx_epc_cgroup *epc_cg;
	bool ret = true;

	/*
	 * Caller ensure css_root ref acquired
	 */
	css_root = &root->css;

	rcu_read_lock();
	css_for_each_descendant_pre(pos, css_root) {
		if (!css_tryget(pos))
			break;

		rcu_read_unlock();

		epc_cg = sgx_epc_cgroup_from_misc_cg(css_misc(pos));

		spin_lock(&epc_cg->lru.lock);
		ret = list_empty(&epc_cg->lru.reclaimable);
		spin_unlock(&epc_cg->lru.lock);

		rcu_read_lock();
		css_put(pos);
		if (!ret)
			break;
	}

	rcu_read_unlock();

	return ret;
}

/**
 * sgx_epc_cgroup_isolate_pages() - walk a cgroup tree and scan LRUs to select pages for
 * reclamation
 * @root:	root of the tree to start walking
 * @nr_to_scan: The number of pages to scan
 * @dst:	Destination list to hold the isolated pages
 */
void sgx_epc_cgroup_isolate_pages(struct misc_cg *root,
				  unsigned int nr_to_scan, struct list_head *dst)
{
	struct cgroup_subsys_state *css_root;
	struct cgroup_subsys_state *pos;
	struct sgx_epc_cgroup *epc_cg;

	if (!nr_to_scan)
		return;

	 /* Caller ensure css_root ref acquired */
	css_root = &root->css;

	rcu_read_lock();
	css_for_each_descendant_pre(pos, css_root) {
		if (!css_tryget(pos))
			break;
		rcu_read_unlock();

		epc_cg = sgx_epc_cgroup_from_misc_cg(css_misc(pos));
		nr_to_scan = sgx_isolate_epc_pages(&epc_cg->lru, nr_to_scan, dst);

		rcu_read_lock();
		css_put(pos);
		if (!nr_to_scan)
			break;
	}

	rcu_read_unlock();
}

static unsigned int sgx_epc_cgroup_reclaim_pages(unsigned int nr_pages,
						 struct misc_cg *root, bool indirect)
{
	LIST_HEAD(iso);
	/*
	 * Attempting to reclaim only a few pages will often fail and is inefficient, while
	 * reclaiming a huge number of pages can result in soft lockups due to holding various
	 * locks for an extended duration.
	 */
	nr_pages = max(nr_pages, SGX_EPC_RECLAIM_MIN_PAGES);
	nr_pages = min(nr_pages, SGX_NR_TO_SCAN_MAX);
	sgx_epc_cgroup_isolate_pages(root, nr_pages, &iso);

	return sgx_do_epc_reclamation(&iso, indirect);
}

/*
 * Scheduled by sgx_epc_cgroup_try_charge() to reclaim pages from the cgroup when the cgroup is
 * at/near its maximum capacity
 */
static void sgx_epc_cgroup_reclaim_work_func(struct work_struct *work)
{
	struct sgx_epc_cgroup *epc_cg;
	u64 cur, max;

	epc_cg = container_of(work, struct sgx_epc_cgroup, reclaim_work);

	for (;;) {
		max = sgx_epc_cgroup_max_pages_to_root(epc_cg);

		/*
		 * Adjust the limit down by one page, the goal is to free up
		 * pages for fault allocations, not to simply obey the limit.
		 * Conditionally decrementing max also means the cur vs. max
		 * check will correctly handle the case where both are zero.
		 */
		if (max)
			max--;

		/*
		 * Unless the limit is extremely low, in which case forcing
		 * reclaim will likely cause thrashing, force the cgroup to
		 * reclaim at least once if it's operating *near* its maximum
		 * limit by adjusting @max down by half the min reclaim size.
		 * This work func is scheduled by sgx_epc_cgroup_try_charge
		 * when it cannot directly reclaim due to being in an atomic
		 * context, e.g. EPC allocation in a fault handler.  Waiting
		 * to reclaim until the cgroup is actually at its limit is less
		 * performant as it means the faulting task is effectively
		 * blocked until a worker makes its way through the global work
		 * queue.
		 */
		if (max > SGX_NR_TO_SCAN_MAX)
			max -= (SGX_EPC_RECLAIM_MIN_PAGES / 2);

		cur = sgx_epc_cgroup_page_counter_read(epc_cg);

		if (cur <= max || sgx_epc_cgroup_lru_empty(epc_cg->cg))
			break;

		/* Keep reclaiming until above condition is met. */
		sgx_epc_cgroup_reclaim_pages((unsigned int)(cur - max), epc_cg->cg, true);
	}
}

static int __sgx_epc_cgroup_try_charge(struct sgx_epc_cgroup *epc_cg,
				       bool reclaim)
{
	for (;;) {
		if (!misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg,
					PAGE_SIZE))
			break;

		if (sgx_epc_cgroup_lru_empty(epc_cg->cg))
			return -ENOMEM;

		if (signal_pending(current))
			return -ERESTARTSYS;

		if (!reclaim) {
			queue_work(sgx_epc_cg_wq, &epc_cg->reclaim_work);
			return -EBUSY;
		}

		if (!sgx_epc_cgroup_reclaim_pages(1, epc_cg->cg, false))
			/* All pages were too young to reclaim, try again */
			schedule();
	}

	return 0;
}

/**
 * sgx_epc_cgroup_try_charge() - hierarchically try to charge a single EPC page
 * @reclaim:		whether or not synchronous reclaim is allowed
 *
 * Returns EPC cgroup or NULL on success, -errno on failure.
 */
struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(bool reclaim)
{
	struct sgx_epc_cgroup *epc_cg;
	int ret;

	if (sgx_epc_cgroup_disabled())
		return NULL;

	epc_cg = sgx_epc_cgroup_from_misc_cg(get_current_misc_cg());
	ret = __sgx_epc_cgroup_try_charge(epc_cg, reclaim);

	if (ret) {
		/* No epc_cg returned, release ref from get_current_misc_cg() */
		put_misc_cg(epc_cg->cg);
		return ERR_PTR(ret);
	}

	/* Ref released in sgx_epc_cgroup_uncharge() */
	return epc_cg;
}

/**
 * sgx_epc_cgroup_uncharge() - hierarchically uncharge EPC pages
 * @epc_cg:	the charged epc cgroup
 */
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg)
{
	if (sgx_epc_cgroup_disabled())
		return;

	misc_cg_uncharge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE);

	/* Ref got from sgx_epc_cgroup_try_charge() */
	put_misc_cg(epc_cg->cg);
}

static void sgx_epc_cgroup_free(struct misc_cg *cg)
{
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = sgx_epc_cgroup_from_misc_cg(cg);
	if (!epc_cg)
		return;

	cancel_work_sync(&epc_cg->reclaim_work);
	kfree(epc_cg);
}

static int sgx_epc_cgroup_alloc(struct misc_cg *cg);

const struct misc_operations_struct sgx_epc_cgroup_ops = {
	.alloc = sgx_epc_cgroup_alloc,
	.free = sgx_epc_cgroup_free,
};

static int sgx_epc_cgroup_alloc(struct misc_cg *cg)
{
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = kzalloc(sizeof(*epc_cg), GFP_KERNEL);
	if (!epc_cg)
		return -ENOMEM;

	sgx_lru_init(&epc_cg->lru);
	INIT_WORK(&epc_cg->reclaim_work, sgx_epc_cgroup_reclaim_work_func);
	cg->res[MISC_CG_RES_SGX_EPC].misc_ops = &sgx_epc_cgroup_ops;
	cg->res[MISC_CG_RES_SGX_EPC].priv = epc_cg;
	epc_cg->cg = cg;
	return 0;
}

static int __init sgx_epc_cgroup_init(void)
{
	struct misc_cg *cg;

	if (!boot_cpu_has(X86_FEATURE_SGX))
		return 0;

	sgx_epc_cg_wq = alloc_workqueue("sgx_epc_cg_wq",
					WQ_UNBOUND | WQ_FREEZABLE,
					WQ_UNBOUND_MAX_ACTIVE);
	BUG_ON(!sgx_epc_cg_wq);

	cg = misc_cg_root();
	BUG_ON(!cg);

	return sgx_epc_cgroup_alloc(cg);
}
subsys_initcall(sgx_epc_cgroup_init);
