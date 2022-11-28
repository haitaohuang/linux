/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */
#ifndef _INTEL_SGX_EPC_CGROUP_H_
#define _INTEL_SGX_EPC_CGROUP_H_

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

static inline struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(bool reclaim)
{
	return NULL;
}

static inline void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg) { }

static inline void sgx_epc_cgroup_isolate_pages(struct sgx_epc_cgroup *root,
						size_t *nr_to_scan,
						struct list_head *dst) { }

static inline struct sgx_epc_lru_lists *epc_cg_lru(struct sgx_epc_cgroup *epc_cg)
{
	return NULL;
}

static bool sgx_epc_cgroup_lru_empty(struct sgx_epc_cgroup *root)
{
	return true;
}
#else
struct sgx_epc_cgroup {
	struct misc_cg *cg;
	struct sgx_epc_lru_lists	lru;
	struct work_struct	reclaim_work;
};

struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(bool reclaim);
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg);
bool sgx_epc_cgroup_lru_empty(struct sgx_epc_cgroup *root);
void sgx_epc_cgroup_isolate_pages(struct sgx_epc_cgroup *root,
				  size_t *nr_to_scan, struct list_head *dst);
static inline struct sgx_epc_lru_lists *epc_cg_lru(struct sgx_epc_cgroup *epc_cg)
{
	if (epc_cg)
		return &epc_cg->lru;
	return NULL;
}
#endif

#endif /* _INTEL_SGX_EPC_CGROUP_H_ */
