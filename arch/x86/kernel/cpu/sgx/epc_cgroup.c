// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2022 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/threads.h>

#include "epc_cgroup.h"

#define SGX_EPC_RECLAIM_MIN_PAGES		16UL
#define SGX_EPC_RECLAIM_MAX_PAGES		64UL
#define SGX_EPC_RECLAIM_IGNORE_AGE_THRESHOLD	5
#define SGX_EPC_RECLAIM_OOM_THRESHOLD		5

static struct workqueue_struct *sgx_epc_cg_wq;

struct sgx_epc_reclaim_control {
	struct sgx_epc_cgroup *epc_cg;
	int nr_fails;
	bool ignore_age;
};

static inline unsigned long sgx_epc_cgroup_page_counter_read(struct sgx_epc_cgroup *epc_cg)
{
	 return atomic_long_read(&epc_cg->cg->res[MISC_CG_RES_SGX_EPC].usage) / PAGE_SIZE;
}

static inline unsigned long sgx_epc_cgroup_max_pages(struct sgx_epc_cgroup *epc_cg)
{
	 return READ_ONCE(epc_cg->cg->res[MISC_CG_RES_SGX_EPC].max) / PAGE_SIZE;
}

static inline struct sgx_epc_cgroup *sgx_epc_cgroup_from_misc_cg(struct misc_cg *cg)
{
	if (cg)
		return (struct sgx_epc_cgroup *)(cg->res[MISC_CG_RES_SGX_EPC].priv);

	return NULL;
}

static inline struct sgx_epc_cgroup *parent_epc_cgroup(struct sgx_epc_cgroup *epc_cg)
{
	return sgx_epc_cgroup_from_misc_cg(misc_cg_parent(epc_cg->cg));
}

static inline bool sgx_epc_cgroup_disabled(void)
{
	return !cgroup_subsys_enabled(misc_cgrp_subsys);
}

/**
 * sgx_epc_cgroup_iter - iterate over the EPC cgroup hierarchy
 * @root:		hierarchy root
 * @prev:		previously returned epc_cg, NULL on first invocation
 * @reclaim_epoch:	epoch for shared reclaim walks, NULL for full walks
 *
 * Return: references to children of the hierarchy below @root, or
 * @root itself, or %NULL after a full round-trip.
 *
 * Caller must pass the return value in @prev on subsequent invocations
 * for reference counting, or use sgx_epc_cgroup_iter_break() to cancel
 * a hierarchy walk before the round-trip is complete.
 */
static struct sgx_epc_cgroup *sgx_epc_cgroup_iter(struct sgx_epc_cgroup *prev,
						  struct sgx_epc_cgroup *root,
						  unsigned long *reclaim_epoch)
{
	struct cgroup_subsys_state *css = NULL;
	struct sgx_epc_cgroup *epc_cg = NULL;
	struct sgx_epc_cgroup *pos = NULL;
	bool inc_epoch = false;

	if (sgx_epc_cgroup_disabled())
		return NULL;

	if (!root)
		root = sgx_epc_cgroup_from_misc_cg(misc_cg_root());

	if (prev && !reclaim_epoch)
		pos = prev;

	rcu_read_lock();

start:
	if (reclaim_epoch) {
		/*
		 * Abort the walk if a reclaimer working from the same root has
		 * started a new walk after this reclaimer has already scanned
		 * at least one cgroup.
		 */
		if (prev && *reclaim_epoch != root->epoch)
			goto out;

		while (1) {
			pos = READ_ONCE(root->reclaim_iter);
			if (!pos || css_tryget(&pos->cg->css))
				break;

			/*
			 * The css is dying, clear the reclaim_iter immediately
			 * instead of waiting for ->css_released to be called.
			 * Busy waiting serves no purpose and attempting to wait
			 * for ->css_released may actually block it from being
			 * called.
			 */
			(void)cmpxchg(&root->reclaim_iter, pos, NULL);
		}
	}

	if (pos)
		css = &pos->cg->css;

	while (!epc_cg) {
		struct misc_cg *cg;

		css = css_next_descendant_pre(css, &root->cg->css);
		if (!css) {
			/*
			 * Increment the epoch as we've reached the end of the
			 * tree and the next call to css_next_descendant_pre
			 * will restart at root.  Do not update root->epoch
			 * directly as we should only do so if we update the
			 * reclaim_iter, i.e. a different thread may win the
			 * race and update the epoch for us.
			 */
			inc_epoch = true;

			/*
			 * Reclaimers share the hierarchy walk, and a new one
			 * might jump in at the end of the hierarchy.  Restart
			 * at root so that  we don't return NULL on a thread's
			 * initial call.
			 */
			if (!prev)
				continue;
			break;
		}

		cg = css_misc(css);
		/*
		 * Verify the css and acquire a reference.  Don't take an
		 * extra reference to root as it's either the global root
		 * or is provided by the caller and so is guaranteed to be
		 * alive.  Keep walking if this css is dying.
		 */
		if (cg != root->cg && !css_tryget(&cg->css))
			continue;

		epc_cg = sgx_epc_cgroup_from_misc_cg(cg);
	}

	if (reclaim_epoch) {
		/*
		 * reclaim_iter could have already been updated by a competing
		 * thread; check that the value hasn't changed since we read
		 * it to avoid reclaiming from the same cgroup twice.  If the
		 * value did change, put all of our references and restart the
		 * entire process, for all intents and purposes we're making a
		 * new call.
		 */
		if (cmpxchg(&root->reclaim_iter, pos, epc_cg) != pos) {
			if (epc_cg && epc_cg != root)
				put_misc_cg(epc_cg->cg);
			if (pos)
				put_misc_cg(pos->cg);
			css = NULL;
			epc_cg = NULL;
			inc_epoch = false;
			goto start;
		}

		if (inc_epoch)
			root->epoch++;
		if (!prev)
			*reclaim_epoch = root->epoch;

		if (pos)
			put_misc_cg(pos->cg);
	}

out:
	rcu_read_unlock();
	if (prev && prev != root)
		put_misc_cg(prev->cg);

	return epc_cg;
}

/**
 * sgx_epc_cgroup_iter_break - abort a hierarchy walk prematurely
 * @prev:	last visited cgroup as returned by sgx_epc_cgroup_iter()
 * @root:	hierarchy root
 */
static void sgx_epc_cgroup_iter_break(struct sgx_epc_cgroup *prev,
				      struct sgx_epc_cgroup *root)
{
	if (!root)
		root = sgx_epc_cgroup_from_misc_cg(misc_cg_root());
	if (prev && prev != root)
		put_misc_cg(prev->cg);
}

/**
 * sgx_epc_cgroup_lru_empty - check if a cgroup tree has no pages on its lrus
 * @root:	root of the tree to check
 *
 * Return: %true if all cgroups under the specified root have empty LRU lists.
 * Used to avoid livelocks due to a cgroup having a non-zero charge count but
 * no pages on its LRUs, e.g. due to a dead enclave waiting to be released or
 * because all pages in the cgroup are unreclaimable.
 */
bool sgx_epc_cgroup_lru_empty(struct sgx_epc_cgroup *root)
{
	struct sgx_epc_cgroup *epc_cg;

	for (epc_cg = sgx_epc_cgroup_iter(NULL, root, NULL);
	     epc_cg;
	     epc_cg = sgx_epc_cgroup_iter(epc_cg, root, NULL)) {
		if (!list_empty(&epc_cg->lru.reclaimable)) {
			sgx_epc_cgroup_iter_break(epc_cg, root);
			return false;
		}
	}
	return true;
}

/**
 * sgx_epc_cgroup_isolate_pages - walk a cgroup tree and separate pages
 * @root:	root of the tree to start walking
 * @nr_to_scan: The number of pages that need to be isolated
 * @dst:	Destination list to hold the isolated pages
 *
 * Walk the cgroup tree and isolate the pages in the hierarchy
 * for reclaiming.
 */
void sgx_epc_cgroup_isolate_pages(struct sgx_epc_cgroup *root,
				  int *nr_to_scan, struct list_head *dst)
{
        struct sgx_epc_cgroup *epc_cg;
        unsigned long epoch;

	if (!*nr_to_scan)
		return;

        for (epc_cg = sgx_epc_cgroup_iter(NULL, root, &epoch);
             epc_cg;
             epc_cg = sgx_epc_cgroup_iter(epc_cg, root, &epoch)) {
                sgx_isolate_epc_pages(&epc_cg->lru, nr_to_scan, dst);
                if (!*nr_to_scan) {
                        sgx_epc_cgroup_iter_break(epc_cg, root);
                        break;
                }
        }
}

static int sgx_epc_cgroup_reclaim_pages(unsigned long nr_pages,
					struct sgx_epc_reclaim_control *rc)
{
	/*
	 * Ensure sgx_reclaim_pages is called with a minimum and maximum
	 * number of pages.  Attempting to reclaim only a few pages will
	 * often fail and is inefficient, while reclaiming a huge number
	 * of pages can result in soft lockups due to holding various
	 * locks for an extended duration.  This also bounds nr_pages so
	 */
	nr_pages = max(nr_pages, SGX_EPC_RECLAIM_MIN_PAGES);
	nr_pages = min(nr_pages, SGX_EPC_RECLAIM_MAX_PAGES);

	return sgx_reclaim_epc_pages(nr_pages, rc->ignore_age, rc->epc_cg);
}

static int sgx_epc_cgroup_reclaim_failed(struct sgx_epc_reclaim_control *rc)
{
	if (sgx_epc_cgroup_lru_empty(rc->epc_cg))
		return -ENOMEM;

	++rc->nr_fails;
	if (rc->nr_fails > SGX_EPC_RECLAIM_IGNORE_AGE_THRESHOLD)
		rc->ignore_age = true;

	return 0;
}

static inline
void sgx_epc_reclaim_control_init(struct sgx_epc_reclaim_control *rc,
				  struct sgx_epc_cgroup *epc_cg)
{
	rc->epc_cg = epc_cg;
	rc->nr_fails = 0;
	rc->ignore_age = false;
}

/*
 * Scheduled by sgx_epc_cgroup_try_charge() to reclaim pages from the
 * cgroup when the cgroup is at/near its maximum capacity
 */
static void sgx_epc_cgroup_reclaim_work_func(struct work_struct *work)
{
	struct sgx_epc_reclaim_control rc;
	struct sgx_epc_cgroup *epc_cg;
	unsigned long cur, max;

	epc_cg = container_of(work, struct sgx_epc_cgroup, reclaim_work);

	sgx_epc_reclaim_control_init(&rc, epc_cg);

	for (;;) {
		max = sgx_epc_cgroup_max_pages(epc_cg);

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
		if (max > SGX_EPC_RECLAIM_MAX_PAGES)
			max -= (SGX_EPC_RECLAIM_MIN_PAGES/2);

		cur = sgx_epc_cgroup_page_counter_read(epc_cg);
		if (cur <= max)
			break;

		if (!sgx_epc_cgroup_reclaim_pages(cur - max, &rc)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc))
				break;
		}
	}
}

static int __sgx_epc_cgroup_try_charge(struct sgx_epc_cgroup *epc_cg,
				       unsigned long nr_pages, bool reclaim)
{
	struct sgx_epc_reclaim_control rc;
	unsigned long cur, max, over;
	unsigned int nr_empty = 0;

	if (epc_cg == sgx_epc_cgroup_from_misc_cg(misc_cg_root())) {
		misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg,
				   nr_pages * PAGE_SIZE);
		return 0;
	}

	sgx_epc_reclaim_control_init(&rc, NULL);

	for (;;) {
		if (!misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg,
					nr_pages * PAGE_SIZE))
			break;

		rc.epc_cg = epc_cg;
		max = sgx_epc_cgroup_max_pages(rc.epc_cg);
		if (nr_pages > max)
			return -ENOMEM;

		if (signal_pending(current))
			return -ERESTARTSYS;

		if (!reclaim) {
			queue_work(sgx_epc_cg_wq, &rc.epc_cg->reclaim_work);
			return -EBUSY;
		}

		cur = sgx_epc_cgroup_page_counter_read(rc.epc_cg);
		over = ((cur + nr_pages) > max) ?
			(cur + nr_pages) - max : SGX_EPC_RECLAIM_MIN_PAGES;

		if (!sgx_epc_cgroup_reclaim_pages(over, &rc)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc)) {
				if (++nr_empty > SGX_EPC_RECLAIM_OOM_THRESHOLD)
					return -ENOMEM;
				schedule();
			}
		}
	}

	css_get_many(&epc_cg->cg->css, nr_pages);

	return 0;
}


/**
 * sgx_epc_cgroup_try_charge - hierarchically try to charge a single EPC page
 * @mm:			the mm_struct of the process to charge
 * @reclaim:		whether or not synchronous reclaim is allowed
 *
 * Returns EPC cgroup or NULL on success, -errno on failure.
 */
struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(struct mm_struct *mm,
						 bool reclaim)
{
	struct sgx_epc_cgroup *epc_cg;
	int ret;

	if (sgx_epc_cgroup_disabled())
		return NULL;

	epc_cg = sgx_epc_cgroup_from_misc_cg(get_current_misc_cg());
	ret = __sgx_epc_cgroup_try_charge(epc_cg, 1, reclaim);
	put_misc_cg(epc_cg->cg);

	if (ret)
		return ERR_PTR(ret);

	return epc_cg;
}

/**
 * sgx_epc_cgroup_uncharge - hierarchically uncharge EPC pages
 * @epc_cg:	the charged epc cgroup
 */
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg)
{
	if (sgx_epc_cgroup_disabled())
		return;

	misc_cg_uncharge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE);

	if (epc_cg->cg != misc_cg_root())
		put_misc_cg(epc_cg->cg);
}

static void sgx_epc_cgroup_oom(struct sgx_epc_cgroup *root)
{
	struct sgx_epc_cgroup *epc_cg;

	for (epc_cg = sgx_epc_cgroup_iter(NULL, root, NULL);
	     epc_cg;
	     epc_cg = sgx_epc_cgroup_iter(epc_cg, root, NULL)) {
		if (sgx_epc_oom(&epc_cg->lru)) {
			sgx_epc_cgroup_iter_break(epc_cg, root);
			return;
		}
	}
}

static void sgx_epc_cgroup_released(struct misc_cg *cg)
{
	struct sgx_epc_cgroup *dead_cg;
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = sgx_epc_cgroup_from_misc_cg(cg);
	dead_cg = epc_cg;

	while ((epc_cg = parent_epc_cgroup(epc_cg)))
		cmpxchg(&epc_cg->reclaim_iter, dead_cg, NULL);
}

static void sgx_epc_cgroup_free(struct misc_cg *cg)
{
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = sgx_epc_cgroup_from_misc_cg(cg);
	cancel_work_sync(&epc_cg->reclaim_work);
	kfree(epc_cg);
}

static void sgx_epc_cgroup_max_write(struct misc_cg *cg)
{
	struct sgx_epc_reclaim_control rc;
	struct sgx_epc_cgroup *epc_cg;
	unsigned int nr_empty = 0;
	unsigned long cur, max;

	epc_cg = sgx_epc_cgroup_from_misc_cg(cg);

	sgx_epc_reclaim_control_init(&rc, epc_cg);

	max = sgx_epc_cgroup_max_pages(epc_cg);

	for (;;) {
		cur = sgx_epc_cgroup_page_counter_read(epc_cg);
		if (cur <= max)
			break;

		if (signal_pending(current))
			break;

		if (!sgx_epc_cgroup_reclaim_pages(cur - max, &rc)) {
			if (sgx_epc_cgroup_reclaim_failed(&rc)) {
				if (++nr_empty > SGX_EPC_RECLAIM_OOM_THRESHOLD)
					sgx_epc_cgroup_oom(epc_cg);
				schedule();
			}
		}
	}
}

static int sgx_epc_cgroup_alloc(struct misc_cg *cg)
{
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = kzalloc(sizeof(struct sgx_epc_cgroup), GFP_KERNEL);
	if (!epc_cg)
		return -ENOMEM;

	sgx_lru_init(&epc_cg->lru);
	INIT_WORK(&epc_cg->reclaim_work, sgx_epc_cgroup_reclaim_work_func);
	cg->res[MISC_CG_RES_SGX_EPC].misc_cg_alloc = sgx_epc_cgroup_alloc;
	cg->res[MISC_CG_RES_SGX_EPC].misc_cg_free = sgx_epc_cgroup_free;
	cg->res[MISC_CG_RES_SGX_EPC].misc_cg_released = sgx_epc_cgroup_released;
	cg->res[MISC_CG_RES_SGX_EPC].misc_cg_max_write = sgx_epc_cgroup_max_write;
	cg->res[MISC_CG_RES_SGX_EPC].priv = epc_cg;
	epc_cg->cg = cg;
	return 0;
}

static int __init sgx_epc_cgroup_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_SGX))
		return 0;

	sgx_epc_cg_wq = alloc_workqueue("sgx_epc_cg_wq",
					WQ_UNBOUND | WQ_FREEZABLE,
					WQ_UNBOUND_MAX_ACTIVE);
	BUG_ON(!sgx_epc_cg_wq);

	return sgx_epc_cgroup_alloc(misc_cg_root());
}
subsys_initcall(sgx_epc_cgroup_init);
