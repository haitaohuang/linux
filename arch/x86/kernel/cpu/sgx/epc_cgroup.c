// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2022 Intel Corporation.

#include <linux/atomic.h>
#include <linux/kernel.h>
#include "epc_cgroup.h"

/* The root EPC cgroup */
static struct sgx_epc_cgroup epc_cg_root;

/**
 * sgx_epc_cgroup_try_charge() - try to charge cgroup for a single EPC page
 *
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

	kfree(epc_cg);
}

static int sgx_epc_cgroup_alloc(struct misc_cg *cg);

const struct misc_res_ops sgx_epc_cgroup_ops = {
	.alloc = sgx_epc_cgroup_alloc,
	.free = sgx_epc_cgroup_free,
};

static void sgx_epc_misc_init(struct misc_cg *cg, struct sgx_epc_cgroup *epc_cg)
{
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
	misc_cg_set_ops(MISC_CG_RES_SGX_EPC, &sgx_epc_cgroup_ops);
	sgx_epc_misc_init(misc_cg_root(), &epc_cg_root);
}
