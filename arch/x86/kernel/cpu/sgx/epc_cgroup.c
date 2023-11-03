// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2022 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include "epc_cgroup.h"

/* The root EPC cgroup */
static struct sgx_epc_cgroup epc_cg_root;

/*
 * The work queue that reclaims EPC pages in the background for cgroups.
 *
 * A cgroup schedules a work item into this queue to reclaim pages within the
 * same cgroup when its usage limit is reached and synchronous reclamation is not
 * an option, e.g., in a fault handler.
 */
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
 * sgx_epc_cgroup_reclaim_work_func() to determine if EPC usage of a cgroup is
 * over its limit or its ancestors' hence reclamation is needed.
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

/**
 * sgx_epc_cgroup_lru_empty() - check if a cgroup tree has no pages on its LRUs
 * @root:	Root of the tree to check
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
 * sgx_epc_cgroup_reclaim_pages() - walk a cgroup tree and scan LRUs to reclaim pages
 * @root:	Root of the tree to start walking from.
 * @indirect:   In ksgxd or EPC cgroup work queue context.
 * Return:	Number of pages reclaimed.
 */
static unsigned int sgx_epc_cgroup_reclaim_pages(struct misc_cg *root, bool indirect)
{
	/*
	 * Attempting to reclaim only a few pages will often fail and is
	 * inefficient, while reclaiming a huge number of pages can result in
	 * soft lockups due to holding various locks for an extended duration.
	 */
	unsigned int nr_to_scan = SGX_NR_TO_SCAN;
	struct cgroup_subsys_state *css_root;
	struct cgroup_subsys_state *pos;
	struct sgx_epc_cgroup *epc_cg;
	unsigned int cnt;

	 /* Caller ensure css_root ref acquired */
	css_root = &root->css;

	cnt = 0;
	rcu_read_lock();
	css_for_each_descendant_pre(pos, css_root) {
		if (!css_tryget(pos))
			break;
		rcu_read_unlock();

		epc_cg = sgx_epc_cgroup_from_misc_cg(css_misc(pos));
		cnt += sgx_reclaim_pages(&epc_cg->lru, &nr_to_scan, indirect);

		rcu_read_lock();
		css_put(pos);
		if (!nr_to_scan)
			break;
	}

	rcu_read_unlock();
	return cnt;
}

/*
 * Scheduled by sgx_epc_cgroup_try_charge() to reclaim pages from the cgroup
 * when the cgroup is at/near its maximum capacity
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
		if (max > SGX_NR_TO_SCAN * 2)
			max -= (SGX_NR_TO_SCAN / 2);

		cur = sgx_epc_cgroup_page_counter_read(epc_cg);

		if (cur <= max || sgx_epc_cgroup_lru_empty(epc_cg->cg))
			break;

		/* Keep reclaiming until above condition is met. */
		sgx_epc_cgroup_reclaim_pages(epc_cg->cg, true);
	}
}

/**
 * sgx_epc_cgroup_try_charge() - try to charge cgroup for a single EPC page
 * @epc_cg:	The EPC cgroup to be charged for the page.
 * Return:
 * * %0 - If successfully charged.
 * * -errno - for failures.
 */
int sgx_epc_cgroup_try_charge(struct sgx_epc_cgroup *epc_cg)
{
	return misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE);
}

/**
 * sgx_epc_cgroup_uncharge() - uncharge a cgroup for an EPC page
 * @epc_cg:	The charged epc cgroup
 */
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg)
{
	misc_cg_uncharge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE);
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

const struct misc_res_ops sgx_epc_cgroup_ops = {
	.alloc = sgx_epc_cgroup_alloc,
	.free = sgx_epc_cgroup_free,
};

static void sgx_epc_misc_init(struct misc_cg *cg, struct sgx_epc_cgroup *epc_cg)
{
	sgx_lru_init(&epc_cg->lru);
	INIT_WORK(&epc_cg->reclaim_work, sgx_epc_cgroup_reclaim_work_func);
	cg->res[MISC_CG_RES_SGX_EPC].priv = epc_cg;
	epc_cg->cg = cg;
}

static int sgx_epc_cgroup_alloc(struct misc_cg *cg)
{
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = kzalloc(sizeof(*epc_cg), GFP_KERNEL);
	if (!epc_cg)
		return -ENOMEM;

	sgx_epc_misc_init(cg, epc_cg);

	return 0;
}

void sgx_epc_cgroup_init(void)
{
	sgx_epc_cg_wq = alloc_workqueue("sgx_epc_cg_wq",
					WQ_UNBOUND | WQ_FREEZABLE,
					WQ_UNBOUND_MAX_ACTIVE);
	BUG_ON(!sgx_epc_cg_wq);

	misc_cg_set_ops(MISC_CG_RES_SGX_EPC, &sgx_epc_cgroup_ops);
	sgx_epc_misc_init(misc_cg_root(), &epc_cg_root);
}
