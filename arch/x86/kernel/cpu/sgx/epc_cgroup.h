/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */
#ifndef _SGX_EPC_CGROUP_H_
#define _SGX_EPC_CGROUP_H_

#include <asm/sgx.h>
#include <linux/cgroup.h>
#include <linux/list.h>
#include <linux/misc_cgroup.h>
#include <linux/page_counter.h>
#include <linux/workqueue.h>

#include "sgx.h"

#ifndef CONFIG_CGROUP_SGX_EPC
#define MISC_CG_RES_SGX_EPC MISC_CG_RES_TYPES
struct sgx_epc_cgroup;

static inline struct sgx_epc_cgroup *sgx_get_current_epc_cg(void)
{
	return NULL;
}

static inline void sgx_put_epc_cg(struct sgx_epc_cgroup *epc_cg) { }

static inline int sgx_epc_cgroup_try_charge(struct sgx_epc_cgroup *epc_cg, bool reclaim)
{
	return 0;
}

static inline void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg) { }

static inline void sgx_epc_cgroup_init(void) { }
#else
struct sgx_epc_cgroup {
	struct misc_cg *cg;
	struct sgx_epc_lru_list lru;
	struct work_struct reclaim_work;
};

static inline struct sgx_epc_cgroup *sgx_epc_cgroup_from_misc_cg(struct misc_cg *cg)
{
	return (struct sgx_epc_cgroup *)(cg->res[MISC_CG_RES_SGX_EPC].priv);
}

/**
 * sgx_get_current_epc_cg() - get the EPC cgroup of current process.
 *
 * Returned cgroup has its ref count increased by 1. Caller must call
 * sgx_put_epc_cg() to return the reference.
 *
 * Return: EPC cgroup to which the current task belongs to.
 */
static inline struct sgx_epc_cgroup *sgx_get_current_epc_cg(void)
{
	return sgx_epc_cgroup_from_misc_cg(get_current_misc_cg());
}

/**
 * sgx_put_epc_cg() - Put the EPC cgroup and reduce its ref count.
 * @epc_cg - EPC cgroup to put.
 */
static inline void sgx_put_epc_cg(struct sgx_epc_cgroup *epc_cg)
{
	if (epc_cg)
		put_misc_cg(epc_cg->cg);
}

int sgx_epc_cgroup_try_charge(struct sgx_epc_cgroup *epc_cg, bool reclaim);
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg);
bool sgx_epc_cgroup_lru_empty(struct misc_cg *root);
void sgx_epc_cgroup_init(void);

#endif

#endif /* _SGX_EPC_CGROUP_H_ */
