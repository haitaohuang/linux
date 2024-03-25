// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022-2024 Intel Corporation. */

#include<linux/slab.h>
#include "epc_cgroup.h"

/*
 * The minimal free pages maintained by per-cgroup reclaimer
 * Set this to the low threshold used by the global reclaimer, ksgxd.
 */
#define SGX_CG_MIN_FREE_PAGE	(SGX_NR_LOW_PAGES)

/*
 * If the cgroup limit is close to SGX_CG_MIN_FREE_PAGE, maintaining the minimal
 * free pages would barely leave any page for use, causing excessive reclamation
 * and thrashing.
 *
 * Define the following limit, below which cgroup does not maintain the minimal
 * free page threshold. Set this to quadruple of the minimal so at least 75%
 * pages used without being reclaimed.
 */
#define SGX_CG_LOW_LIMIT	(SGX_CG_MIN_FREE_PAGE * 4)

/* The root SGX EPC cgroup */
static struct sgx_cgroup sgx_cg_root;

/*
 * The work queue that reclaims EPC pages in the background for cgroups.
 *
 * A cgroup schedules a work item into this queue to reclaim pages within the
 * same cgroup when its usage limit is reached and synchronous reclamation is not
 * an option, i.e., in a page fault handler.
 */
static struct workqueue_struct *sgx_cg_wq;

static inline u64 sgx_cgroup_page_counter_read(struct sgx_cgroup *sgx_cg)
{
	return atomic64_read(&sgx_cg->cg->res[MISC_CG_RES_SGX_EPC].usage) / PAGE_SIZE;
}

static inline u64 sgx_cgroup_max_pages(struct sgx_cgroup *sgx_cg)
{
	return READ_ONCE(sgx_cg->cg->res[MISC_CG_RES_SGX_EPC].max) / PAGE_SIZE;
}

/*
 * Get the lower bound of limits of a cgroup and its ancestors. Used in
 * sgx_cgroup_should_reclaim() to determine if EPC usage of a cgroup is
 * close to its limit or its ancestors' hence reclamation is needed.
 */
static inline u64 sgx_cgroup_max_pages_to_root(struct sgx_cgroup *sgx_cg)
{
	struct misc_cg *i = sgx_cg->cg;
	u64 m = U64_MAX;

	while (i) {
		m = min(m, READ_ONCE(i->res[MISC_CG_RES_SGX_EPC].max));
		i = misc_cg_parent(i);
	}

	return m / PAGE_SIZE;
}

/**
 * sgx_cgroup_lru_empty() - check if a cgroup tree has no pages on its LRUs
 * @root:	Root of the tree to check
 *
 * Return: %true if all cgroups under the specified root have empty LRU lists.
 */
static bool sgx_cgroup_lru_empty(struct misc_cg *root)
{
	struct cgroup_subsys_state *css_root;
	struct cgroup_subsys_state *pos;
	struct sgx_cgroup *sgx_cg;
	bool ret = true;

	/*
	 * Caller must ensure css_root ref acquired
	 */
	css_root = &root->css;

	rcu_read_lock();
	css_for_each_descendant_pre(pos, css_root) {
		if (!css_tryget(pos))
			break;

		rcu_read_unlock();

		sgx_cg = sgx_cgroup_from_misc_cg(css_misc(pos));

		spin_lock(&sgx_cg->lru.lock);
		ret = list_empty(&sgx_cg->lru.reclaimable);
		spin_unlock(&sgx_cg->lru.lock);

		rcu_read_lock();
		css_put(pos);
		if (!ret)
			break;
	}

	rcu_read_unlock();

	return ret;
}

/**
 * sgx_cgroup_reclaim_pages() - reclaim EPC from a cgroup tree
 * @root:	The root of cgroup tree to reclaim from.
 *
 * This function performs a pre-order walk in the cgroup tree under the given
 * root, attempting to reclaim pages at each node until a fixed number of pages
 * (%SGX_NR_TO_SCAN) are attempted for reclamation. No guarantee of success on
 * the actual reclamation process. In extreme cases, if all pages in front of
 * the LRUs are recently accessed, i.e., considered "too young" to reclaim, no
 * page will actually be reclaimed after walking the whole tree.
 */
static void sgx_cgroup_reclaim_pages(struct misc_cg *root)
{
	struct cgroup_subsys_state *css_root;
	struct cgroup_subsys_state *pos;
	struct sgx_cgroup *sgx_cg;
	unsigned int cnt = 0;

	 /* Caller must ensure css_root ref acquired */
	css_root = &root->css;

	rcu_read_lock();
	css_for_each_descendant_pre(pos, css_root) {
		if (!css_tryget(pos))
			break;
		rcu_read_unlock();

		sgx_cg = sgx_cgroup_from_misc_cg(css_misc(pos));
		cnt += sgx_reclaim_pages(&sgx_cg->lru);

		rcu_read_lock();
		css_put(pos);

		if (cnt >= SGX_NR_TO_SCAN)
			break;
	}

	rcu_read_unlock();
}

/**
 * sgx_cgroup_should_reclaim() - check if EPC reclamation is needed for a cgroup
 * @sgx_cg: The cgroup to be checked.
 *
 * This function can be used to guard a call to sgx_cgroup_reclaim_pages() where
 * the minimal number of free page needs be maintained for the cgroup to make
 * good forward progress.
 *
 * Return: %true if number of free pages available for the cgroup below a
 * threshold (%SGX_CG_MIN_FREE_PAGE) and there are reclaimable pages within the
 * cgroup.
 */
static bool sgx_cgroup_should_reclaim(struct sgx_cgroup *sgx_cg)
{
	u64 cur, max;

	if (sgx_cgroup_lru_empty(sgx_cg->cg))
		return false;

	max = sgx_cgroup_max_pages_to_root(sgx_cg);

	/*
	 * Unless the limit is very low, maintain a minimal number of free pages
	 * so there is always a few pages available to serve new allocation
	 * requests quickly.
	 */
	if (max > SGX_CG_LOW_LIMIT)
		max -= SGX_CG_MIN_FREE_PAGE;

	cur = sgx_cgroup_page_counter_read(sgx_cg);

	return (cur >= max);
}

/*
 * Asynchronous work flow to reclaim pages from the cgroup when the cgroup is
 * at/near its maximum capacity.
 */
static void sgx_cgroup_reclaim_work_func(struct work_struct *work)
{
	struct sgx_cgroup *sgx_cg = container_of(work, struct sgx_cgroup, reclaim_work);

	/*
	 * This work func is scheduled by sgx_cgroup_try_charge() when it cannot
	 * directly reclaim, i.e., EPC allocation in a fault handler. Waiting to
	 * reclaim until the cgroup is actually at its limit is less performant,
	 * as it means the task scheduling this asynchronous work is effectively
	 * blocked until a worker makes its way through the global work queue.
	 */
	while (sgx_cgroup_should_reclaim(sgx_cg)) {
		sgx_cgroup_reclaim_pages(sgx_cg->cg);
		cond_resched();
	}
}

static int __sgx_cgroup_try_charge(struct sgx_cgroup *epc_cg)
{
	if (!misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE))
		return 0;

	/* No reclaimable pages left in the cgroup */
	if (sgx_cgroup_lru_empty(epc_cg->cg))
		return -ENOMEM;

	if (signal_pending(current))
		return -ERESTARTSYS;

	return -EBUSY;
}

/**
 * sgx_cgroup_try_charge() - try to charge cgroup for a single EPC page
 * @sgx_cg:	The EPC cgroup to be charged for the page.
 * @reclaim:	Whether or not synchronous EPC reclaim is allowed.
 * Return:
 * * %0 - If successfully charged.
 * * -errno - for failures.
 */
int sgx_cgroup_try_charge(struct sgx_cgroup *sgx_cg, enum sgx_reclaim reclaim)
{
	int ret;

	for (;;) {
		ret = __sgx_cgroup_try_charge(sgx_cg);

		if (ret != -EBUSY)
			return ret;

		if (reclaim == SGX_NO_RECLAIM) {
			queue_work(sgx_cg_wq, &sgx_cg->reclaim_work);
			return -EBUSY;
		}

		sgx_cgroup_reclaim_pages(sgx_cg->cg);
		cond_resched();
	}

	if (sgx_cgroup_should_reclaim(sgx_cg))
		queue_work(sgx_cg_wq, &sgx_cg->reclaim_work);

	return 0;
}

/**
 * sgx_cgroup_uncharge() - uncharge a cgroup for an EPC page
 * @sgx_cg:	The charged sgx cgroup.
 */
void sgx_cgroup_uncharge(struct sgx_cgroup *sgx_cg)
{
	misc_cg_uncharge(MISC_CG_RES_SGX_EPC, sgx_cg->cg, PAGE_SIZE);
}

static void sgx_cgroup_free(struct misc_cg *cg)
{
	struct sgx_cgroup *sgx_cg;

	sgx_cg = sgx_cgroup_from_misc_cg(cg);
	if (!sgx_cg)
		return;

	cancel_work_sync(&sgx_cg->reclaim_work);
	kfree(sgx_cg);
}

static void sgx_cgroup_misc_init(struct misc_cg *cg, struct sgx_cgroup *sgx_cg)
{
	sgx_lru_init(&sgx_cg->lru);
	INIT_WORK(&sgx_cg->reclaim_work, sgx_cgroup_reclaim_work_func);
	cg->res[MISC_CG_RES_SGX_EPC].priv = sgx_cg;
	sgx_cg->cg = cg;
}

static int sgx_cgroup_alloc(struct misc_cg *cg)
{
	struct sgx_cgroup *sgx_cg;

	sgx_cg = kzalloc(sizeof(*sgx_cg), GFP_KERNEL);
	if (!sgx_cg)
		return -ENOMEM;

	sgx_cgroup_misc_init(cg, sgx_cg);

	return 0;
}

const struct misc_res_ops sgx_cgroup_ops = {
	.alloc = sgx_cgroup_alloc,
	.free = sgx_cgroup_free,
};

void sgx_cgroup_init(void)
{
	/*
	 * misc root always exists even if misc is disabled from command line.
	 * Initialize properly.
	 */
	misc_cg_set_ops(MISC_CG_RES_SGX_EPC, &sgx_cgroup_ops);
	sgx_cgroup_misc_init(misc_cg_root(), &sgx_cg_root);

	/*
	 * Only alloc additional resource for workqueue when misc is enabled.
	 * User can disable sgx or disable misc to avoid the failure
	 */
	if (cgroup_subsys_enabled(misc_cgrp_subsys)) {
		sgx_cg_wq = alloc_workqueue("sgx_cg_wq", WQ_UNBOUND | WQ_FREEZABLE,
					    WQ_UNBOUND_MAX_ACTIVE);
		BUG_ON(!sgx_cg_wq);
	}

}
