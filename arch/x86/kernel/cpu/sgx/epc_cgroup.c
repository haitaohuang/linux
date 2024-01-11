// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022-2024 Intel Corporation. */

#include<linux/slab.h>
#include "epc_cgroup.h"

/* The root SGX EPC cgroup */
static struct sgx_cgroup sgx_cg_root;

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
 * @start:	The descendant cgroup from which to start the tree walking.
 *
 * This function performs a pre-order walk in the cgroup tree under the given
 * root, starting from the node %start, or from the root if %start is NULL. The
 * function will attempt to reclaim pages at each node until a fixed number of
 * pages (%SGX_NR_TO_SCAN) are attempted for reclamation. No guarantee of
 * success on the actual reclamation process. In extreme cases, if all pages in
 * front of the LRUs are recently accessed, i.e., considered "too young" to
 * reclaim, no page will actually be reclaimed after walking the whole tree.
 *
 * In some cases, a caller may want to ensure enough reclamation until its
 * specific need is met. In those cases, the caller should invoke this function
 * in a loop, and at each iteration passes in the same root and the next node
 * returned from the previous call as the new %start.
 *
 * Return: The next misc cgroup in the subtree to continue the scanning and
 * attempt for more reclamation from this subtree if needed.  Caller must
 * release the reference if the returned is not used as %start for a subsequent
 * call.
 */
static struct misc_cg *sgx_cgroup_reclaim_pages(struct misc_cg *root, struct misc_cg *start)
{
	struct cgroup_subsys_state *css_root, *pos;
	struct cgroup_subsys_state *next = NULL;
	struct sgx_cgroup *sgx_cg;
	unsigned int cnt = 0;

	 /* Caller must ensure css_root and start ref's acquired */
	css_root = &root->css;
	if (start)
		pos = &start->css;
	else
		pos = css_root;

	while (cnt < SGX_NR_TO_SCAN) {
		sgx_cg = sgx_cgroup_from_misc_cg(css_misc(pos));
		cnt += sgx_reclaim_pages(&sgx_cg->lru);

		rcu_read_lock();

		next = css_next_descendant_pre(pos, css_root);

		if (pos != css_root)
			css_put(pos);

		if (!next || !css_tryget(next)) {
			/* We are done if next is NULL or not safe to continue
			 * the walk if next is dead. Return NULL and the caller
			 * determines whether to restart from root.
			 */
			rcu_read_unlock();
			return NULL;
		}

		rcu_read_unlock();
		pos = next;
	}

	return css_misc(next);
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
	struct misc_cg *cg_next = NULL;

	for (;;) {
		ret = __sgx_cgroup_try_charge(sgx_cg);

		if (ret != -EBUSY)
			goto out;

		if (reclaim == SGX_NO_RECLAIM) {
			ret = -ENOMEM;
			goto out;
		}

		cg_next = sgx_cgroup_reclaim_pages(sgx_cg->cg, cg_next);
		cond_resched();
	}

out:
	if (cg_next != sgx_cg->cg)
		put_misc_cg(cg_next);
	return ret;
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

	kfree(sgx_cg);
}

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

const struct misc_res_ops sgx_cgroup_ops = {
	.alloc = sgx_cgroup_alloc,
	.free = sgx_cgroup_free,
};

int __init sgx_cgroup_init(void)
{
	misc_cg_set_ops(MISC_CG_RES_SGX_EPC, &sgx_cgroup_ops);
	sgx_cgroup_misc_init(misc_cg_root(), &sgx_cg_root);

	return 0;
}
