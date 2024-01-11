// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2022 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include "epc_cgroup.h"

/* The root SGX EPC cgroup */
static struct sgx_cgroup sgx_cg_root;

/**
 * sgx_cgroup_lru_empty() - check if a cgroup tree has no pages on its LRUs
 * @root:	Root of the tree to check
 *
 * Used to avoid livelocks due to a cgroup having a non-zero charge count but
 * no pages on its LRUs, e.g. due to a dead enclave waiting to be released or
 * because all pages in the cgroup are unreclaimable.
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
	 * Caller ensure css_root ref acquired
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
 *
 * Callers check for the need for reclamation before calling this function. Some
 * callers may run this function in a loop guarded by some criteria for
 * triggering reclamation, and call cond_resched() in between iterations to
 * avoid indefinite blocking.
 */
static void sgx_cgroup_reclaim_pages(struct misc_cg *root)
{
	struct cgroup_subsys_state *css_root;
	struct cgroup_subsys_state *pos;
	struct sgx_cgroup *sgx_cg;
	unsigned int cnt = 0;

	 /* Caller ensure css_root ref acquired */
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

static int __sgx_cgroup_try_charge(struct sgx_cgroup *epc_cg)
{
	if (!misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE))
		return 0;

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

		if (reclaim == SGX_NO_RECLAIM)
			return -ENOMEM;

		sgx_cgroup_reclaim_pages(sgx_cg->cg);
		cond_resched();
	}

	return 0;
}

/**
 * sgx_cgroup_uncharge() - uncharge a cgroup for an EPC page
 * @sgx_cg:	The charged sgx cgroup
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

	kfree(sgx_cg);
}

static int sgx_cgroup_alloc(struct misc_cg *cg);

const struct misc_res_ops sgx_cgroup_ops = {
	.alloc = sgx_cgroup_alloc,
	.free = sgx_cgroup_free,
};

static void sgx_cgroup_misc_init(struct misc_cg *cg, struct sgx_cgroup *sgx_cg)
{
	sgx_lru_init(&sgx_cg->lru);
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

void sgx_cgroup_init(void)
{
	misc_cg_set_ops(MISC_CG_RES_SGX_EPC, &sgx_cgroup_ops);
	sgx_cgroup_misc_init(misc_cg_root(), &sgx_cg_root);
}
