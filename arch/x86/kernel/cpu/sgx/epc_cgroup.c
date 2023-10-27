// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2022 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include "epc_cgroup.h"

static inline struct sgx_epc_cgroup *sgx_epc_cgroup_from_misc_cg(struct misc_cg *cg)
{
	return (struct sgx_epc_cgroup *)(cg->res[MISC_CG_RES_SGX_EPC].priv);
}

static inline bool sgx_epc_cgroup_disabled(void)
{
	return !cgroup_subsys_enabled(misc_cgrp_subsys);
}

/**
 * sgx_epc_cgroup_try_charge() - hierarchically try to charge a single EPC page
 *
 * Returns EPC cgroup or NULL on success, -errno on failure.
 */
struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(void)
{
	struct sgx_epc_cgroup *epc_cg;
	int ret;

	if (sgx_epc_cgroup_disabled())
		return NULL;

	epc_cg = sgx_epc_cgroup_from_misc_cg(get_current_misc_cg());
	ret = misc_cg_try_charge(MISC_CG_RES_SGX_EPC, epc_cg->cg, PAGE_SIZE);

	if (!ret) {
		/* No epc_cg returned, release ref from get_current_misc_cg() */
		put_misc_cg(epc_cg->cg);
		return ERR_PTR(-ENOMEM);
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

	cg = misc_cg_root();
	BUG_ON(!cg);

	return sgx_epc_cgroup_alloc(cg);
}
subsys_initcall(sgx_epc_cgroup_init);
