// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include <asm/mman.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

static u32 sgx_calc_ssa_frame_size(u32 miscselect, u64 xfrm)
{
	u32 size_max = PAGE_SIZE;
	u32 size;
	int i;

	for (i = 2; i < 64; i++) {
		if (!((1 << i) & xfrm))
			continue;

		size = SGX_SSA_GPRS_SIZE + sgx_xsave_size_tbl[i];

		if (miscselect & SGX_MISC_EXINFO)
			size += SGX_SSA_MISC_EXINFO_SIZE;

		if (size > size_max)
			size_max = size;
	}

	return PFN_UP(size_max);
}

static int sgx_validate_secs(const struct sgx_secs *secs)
{
	u64 max_size = (secs->attributes & SGX_ATTR_MODE64BIT) ?
		       sgx_encl_size_max_64 : sgx_encl_size_max_32;

	if (secs->size < (2 * PAGE_SIZE) || !is_power_of_2(secs->size))
		return -EINVAL;

	if (secs->base & (secs->size - 1))
		return -EINVAL;

	if (secs->size > max_size)
		return -EINVAL;

	if (!(secs->xfrm & XFEATURE_MASK_FP) ||
	    !(secs->xfrm & XFEATURE_MASK_SSE) ||
	    (((secs->xfrm >> XFEATURE_BNDREGS) & 1) != ((secs->xfrm >> XFEATURE_BNDCSR) & 1)))
		return -EINVAL;

	if (!secs->ssa_frame_size)
		return -EINVAL;

	if (sgx_calc_ssa_frame_size(secs->miscselect, secs->xfrm) > secs->ssa_frame_size)
		return -EINVAL;

	if (memchr_inv(secs->reserved1, 0, sizeof(secs->reserved1)) ||
	    memchr_inv(secs->reserved2, 0, sizeof(secs->reserved2)) ||
	    memchr_inv(secs->reserved3, 0, sizeof(secs->reserved3)) ||
	    memchr_inv(secs->reserved4, 0, sizeof(secs->reserved4)))
		return -EINVAL;

	return 0;
}

static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	struct sgx_epc_page *secs_epc;
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	unsigned long encl_size;
	long ret;

	if (sgx_validate_secs(secs)) {
		pr_debug("invalid SECS\n");
		return -EINVAL;
	}

	/* The extra page goes to SECS. */
	encl_size = secs->size + PAGE_SIZE;

	secs_epc = __sgx_alloc_epc_page();
	if (IS_ERR(secs_epc))
		return PTR_ERR(secs_epc);

	encl->secs.epc_page = secs_epc;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)secs;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));

	ret = __ecreate((void *)&pginfo, sgx_get_epc_virt_addr(secs_epc));
	if (ret) {
		pr_debug("ECREATE returned %ld\n", ret);
		goto err_out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		atomic_or(SGX_ENCL_DEBUG, &encl->flags);

	encl->secs.encl = encl;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssa_frame_size;

	/*
	 * Set SGX_ENCL_CREATED only after the enclave is fully prepped.  This
	 * allows setting and checking enclave creation without having to take
	 * encl->lock.
	 */
	atomic_or(SGX_ENCL_CREATED, &encl->flags);

	return 0;

err_out:
	sgx_free_epc_page(encl->secs.epc_page);
	encl->secs.epc_page = NULL;

	return ret;
}

/**
 * sgx_ioc_enclave_create - handler for %SGX_IOC_ENCLAVE_CREATE
 * @encl:	an enclave pointer
 * @arg:	userspace pointer to a struct sgx_enclave_create instance
 *
 * Allocate kernel data structures for a new enclave and execute ECREATE after
 * checking that the provided data for SECS meets the expectations of ECREATE
 * for an uninitialized enclave and size of the address space does not surpass the
 * platform expectations. This validation is done by sgx_validate_secs().
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_create(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_create ecreate;
	void *secs;
	int ret;

	if (atomic_read(&encl->flags) & SGX_ENCL_CREATED)
		return -EINVAL;

	if (copy_from_user(&ecreate, arg, sizeof(ecreate)))
		return -EFAULT;

	secs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!secs)
		return -ENOMEM;

	if (copy_from_user(secs, (void __user *)ecreate.src, PAGE_SIZE))
		ret = -EFAULT;
	else
		ret = sgx_encl_create(encl, secs);

	kfree(secs);
	return ret;
}

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct sgx_encl *encl = filep->private_data;
	int ret, encl_flags;

	encl_flags = atomic_fetch_or(SGX_ENCL_IOCTL, &encl->flags);
	if (encl_flags & SGX_ENCL_IOCTL)
		return -EBUSY;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		ret = sgx_ioc_enclave_create(encl, (void __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	atomic_andnot(SGX_ENCL_IOCTL, &encl->flags);
	return ret;
}
