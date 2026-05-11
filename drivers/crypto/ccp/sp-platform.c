// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Processor device driver
 *
 * Copyright (C) 2014,2018 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/ioport.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/ccp.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/acpi.h>
#include <linux/platform_data/psp.h>

#include "ccp-dev.h"

struct sp_platform {
	int coherent;
	unsigned int irq_count;
	bool is_platform_device;
};

static const struct sp_dev_vdata dev_vdata[] = {
	{
		.bar = 0,
#ifdef CONFIG_CRYPTO_DEV_SP_CCP
		.ccp_vdata = &ccpv3_platform,
#endif
	},
};

static const struct acpi_device_id sp_acpi_match[] = {
	{ "AMDI0C00", (kernel_ulong_t)&dev_vdata[0] },
	{ },
};
MODULE_DEVICE_TABLE(acpi, sp_acpi_match);

static const struct of_device_id sp_of_match[] = {
	{ .compatible = "amd,ccp-seattle-v1a",
	  .data = (const void *)&dev_vdata[0] },
	{ },
};
MODULE_DEVICE_TABLE(of, sp_of_match);

static const struct platform_device_id sp_platform_match[] = {
	{ "psp" },
	{ },
};
MODULE_DEVICE_TABLE(platform, sp_platform_match);

static struct sp_dev_vdata *sp_get_of_version(struct platform_device *pdev)
{
	const struct of_device_id *match;

	match = of_match_node(sp_of_match, pdev->dev.of_node);
	if (match && match->data)
		return (struct sp_dev_vdata *)match->data;

	return NULL;
}

static struct sp_dev_vdata *sp_get_acpi_version(struct platform_device *pdev)
{
	const struct acpi_device_id *match;

	match = acpi_match_device(sp_acpi_match, &pdev->dev);
	if (match && match->driver_data)
		return (struct sp_dev_vdata *)match->driver_data;

	return NULL;
}

static void sp_platform_fill_vdata(struct sp_dev_vdata *vdata,
					struct psp_vdata *psp,
					struct sev_vdata *sev,
					const struct psp_platform_data *pdata)
{
	struct sev_vdata sevtmp = {
		.cmdresp_reg = pdata->sev_cmd_resp_reg,
		.cmdbuff_addr_lo_reg = pdata->sev_cmd_buf_lo_reg,
		.cmdbuff_addr_hi_reg = pdata->sev_cmd_buf_hi_reg,
	};
	struct psp_vdata psptmp = {
		.sev = sev,
		.feature_reg = pdata->feature_reg,
		.inten_reg = pdata->irq_en_reg,
		.intsts_reg = pdata->irq_st_reg,
	};

	memcpy(sev, &sevtmp, sizeof(*sev));
	memcpy(psp, &psptmp, sizeof(*psp));
	vdata->psp_vdata = psp;
}

static struct sp_dev_vdata *sp_get_platform_version(struct sp_device *sp)
{
	struct sp_platform *sp_platform = sp->dev_specific;
	struct psp_platform_data *pdata;
	struct device *dev = sp->dev;
	struct sp_dev_vdata *vdata;
	struct psp_vdata *psp;
	struct sev_vdata *sev;

	pdata = dev_get_platdata(dev);
	if (!pdata) {
		dev_err(dev, "missing platform data\n");
		return NULL;
	}

	vdata = devm_kzalloc(dev, sizeof(*vdata) + sizeof(*psp) + sizeof(*sev), GFP_KERNEL);
	if (!vdata)
		return NULL;

	psp = (void *)vdata + sizeof(*vdata);
	sev = (void *)psp + sizeof(*psp);
	sp_platform_fill_vdata(vdata, psp, sev, pdata);

	sp_platform->is_platform_device = true;

	dev_dbg(dev, "PSP feature register:\t%x\n", psp->feature_reg);
	dev_dbg(dev, "PSP IRQ enable register:\t%x\n", psp->inten_reg);
	dev_dbg(dev, "PSP IRQ status register:\t%x\n", psp->intsts_reg);
	dev_dbg(dev, "SEV cmdresp register:\t%x\n", sev->cmdresp_reg);
	dev_dbg(dev, "SEV cmdbuf lo register:\t%x\n", sev->cmdbuff_addr_lo_reg);
	dev_dbg(dev, "SEV cmdbuf hi register:\t%x\n", sev->cmdbuff_addr_hi_reg);
	dev_dbg(dev, "SEV cmdresp IRQ:\t%x\n", pdata->mbox_irq_id);
	dev_dbg(dev, "ACPI cmdresp register:\t%x\n", pdata->acpi_cmd_resp_reg);

	return vdata;
}

static int sp_get_irqs(struct sp_device *sp)
{
	struct sp_platform *sp_platform = sp->dev_specific;
	struct device *dev = sp->dev;
	struct platform_device *pdev = to_platform_device(dev);
	int ret;

	sp_platform->irq_count = platform_irq_count(pdev);

	ret = platform_get_irq(pdev, 0);
	if (ret < 0) {
		dev_notice(dev, "unable to get IRQ (%d)\n", ret);
		return ret;
	}

	sp->psp_irq = ret;
	if (sp_platform->irq_count == 1) {
		sp->ccp_irq = ret;
	} else {
		ret = platform_get_irq(pdev, 1);
		if (ret < 0) {
			dev_notice(dev, "unable to get IRQ (%d)\n", ret);
			return ret;
		}

		sp->ccp_irq = ret;
	}

	return 0;
}

static int sp_platform_probe(struct platform_device *pdev)
{
	struct sp_device *sp;
	struct sp_platform *sp_platform;
	struct device *dev = &pdev->dev;
	enum dev_dma_attr attr;
	int ret;

	ret = -ENOMEM;
	sp = sp_alloc_struct(dev);
	if (!sp)
		goto e_err;

	sp_platform = devm_kzalloc(dev, sizeof(*sp_platform), GFP_KERNEL);
	if (!sp_platform)
		goto e_err;

	sp->dev_specific = sp_platform;
	sp->dev_vdata = pdev->dev.of_node ? sp_get_of_version(pdev)
					 : sp_get_acpi_version(pdev);
	if (!sp->dev_vdata)
		sp->dev_vdata = sp_get_platform_version(sp);
	if (!sp->dev_vdata) {
		ret = -ENODEV;
		dev_err(dev, "missing driver data\n");
		goto e_err;
	}

	sp->io_map = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(sp->io_map)) {
		ret = PTR_ERR(sp->io_map);
		goto e_err;
	}

	attr = device_get_dma_attr(dev);
	if (attr == DEV_DMA_NOT_SUPPORTED && !sp_platform->is_platform_device) {
		dev_err(dev, "DMA is not supported");
		goto e_err;
	}

	sp_platform->coherent = (attr == DEV_DMA_COHERENT);
	if (sp_platform->coherent)
		sp->axcache = CACHE_WB_NO_ALLOC;
	else
		sp->axcache = CACHE_NONE;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(48));
	if (ret) {
		dev_err(dev, "dma_set_mask_and_coherent failed (%d)\n", ret);
		goto e_err;
	}

	ret = sp_get_irqs(sp);
	if (ret)
		goto e_err;

	dev_set_drvdata(dev, sp);

	ret = sp_init(sp);
	if (ret)
		goto e_err;

	dev_notice(dev, "enabled\n");

	return 0;

e_err:
	dev_notice(dev, "initialization failed\n");
	return ret;
}

static void sp_platform_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sp_device *sp = dev_get_drvdata(dev);

	sp_destroy(sp);

	dev_notice(dev, "disabled\n");
}

#ifdef CONFIG_PM
static int sp_platform_suspend(struct platform_device *pdev,
				pm_message_t state)
{
	struct device *dev = &pdev->dev;
	struct sp_device *sp = dev_get_drvdata(dev);

	return sp_suspend(sp);
}

static int sp_platform_resume(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sp_device *sp = dev_get_drvdata(dev);

	return sp_resume(sp);
}
#endif

static struct platform_driver sp_platform_driver = {
	.id_table = sp_platform_match,
	.driver = {
		.name = "ccp",
		.acpi_match_table = sp_acpi_match,
		.of_match_table = sp_of_match,
	},
	.probe = sp_platform_probe,
	.remove = sp_platform_remove,
#ifdef CONFIG_PM
	.suspend = sp_platform_suspend,
	.resume = sp_platform_resume,
#endif
};

int sp_platform_init(void)
{
	return platform_driver_register(&sp_platform_driver);
}

void sp_platform_exit(void)
{
	platform_driver_unregister(&sp_platform_driver);
}
