/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SGX_EPC_CGROUP_H_
#define _SGX_EPC_CGROUP_H_

#include <asm/sgx.h>
#include <linux/cgroup.h>
#include <linux/misc_cgroup.h>

#include "sgx.h"

#ifndef CONFIG_CGROUP_MISC

#define MISC_CG_RES_SGX_EPC MISC_CG_RES_TYPES
struct sgx_cgroup;

static inline struct misc_cg *misc_from_sgx(struct sgx_cgroup *sgx_cg)
{
	return NULL;
}

static inline struct sgx_cgroup *sgx_get_current_cg(void)
{
	return NULL;
}

static inline void sgx_put_cg(struct sgx_cgroup *sgx_cg) { }

static inline int sgx_cgroup_try_charge(struct sgx_cgroup *sgx_cg, enum sgx_reclaim reclaim)
{
	return 0;
}

static inline void sgx_cgroup_uncharge(struct sgx_cgroup *sgx_cg) { }

static inline bool sgx_cgroup_lru_empty(struct misc_cg *root)
{
	return true;
}

static inline bool sgx_cgroup_should_reclaim(struct sgx_cgroup *sgx_cg)
{
	return false;
}

static inline void sgx_cgroup_init(void) { }

static inline void sgx_cgroup_reclaim_pages(struct misc_cg *root, struct mm_struct *charge_mm)
{
}

#else /* CONFIG_CGROUP_MISC */

struct sgx_cgroup {
	struct misc_cg *cg;
	struct sgx_epc_lru_list lru;
	struct work_struct reclaim_work;
};

static inline struct misc_cg *misc_from_sgx(struct sgx_cgroup *sgx_cg)
{
	return sgx_cg->cg;
}

static inline struct sgx_cgroup *sgx_cgroup_from_misc_cg(struct misc_cg *cg)
{
	return (struct sgx_cgroup *)(cg->res[MISC_CG_RES_SGX_EPC].priv);
}

/**
 * sgx_get_current_cg() - get the EPC cgroup of current process.
 *
 * Returned cgroup has its ref count increased by 1. Caller must call
 * sgx_put_cg() to return the reference.
 *
 * Return: EPC cgroup to which the current task belongs to.
 */
static inline struct sgx_cgroup *sgx_get_current_cg(void)
{
	/* get_current_misc_cg() never returns NULL when Kconfig enabled */
	return sgx_cgroup_from_misc_cg(get_current_misc_cg());
}

/**
 * sgx_put_cg() - Put the EPC cgroup and reduce its ref count.
 * @sgx_cg - EPC cgroup to put.
 */
static inline void sgx_put_cg(struct sgx_cgroup *sgx_cg)
{
	put_misc_cg(sgx_cg->cg);
}

int sgx_cgroup_try_charge(struct sgx_cgroup *sgx_cg, enum sgx_reclaim reclaim);
void sgx_cgroup_uncharge(struct sgx_cgroup *sgx_cg);
bool sgx_cgroup_lru_empty(struct misc_cg *root);
bool sgx_cgroup_should_reclaim(struct sgx_cgroup *sgx_cg);
void sgx_cgroup_reclaim_pages(struct misc_cg *root,  struct mm_struct *charge_mm);
void sgx_cgroup_init(void);

#endif /* CONFIG_CGROUP_MISC */

#endif /* _SGX_EPC_CGROUP_H_ */
