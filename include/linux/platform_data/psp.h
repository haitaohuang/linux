/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * psp.h - PSP register offsets parsed from ASPT ACPI table
 */

#ifndef __LINUX_PSP_H
#define __LINUX_PSP_H

#include <linux/types.h>
#include <linux/ioport.h>

struct psp_platform_data {
	int sev_cmd_resp_reg;
	int sev_cmd_buf_lo_reg;
	int sev_cmd_buf_hi_reg;
	int feature_reg;
	int irq_en_reg;
	int irq_st_reg;
	int mbox_irq_id;
	int acpi_cmd_resp_reg;
};

#if IS_ENABLED(CONFIG_ACPI)
int acpi_parse_aspt(struct resource *res, struct psp_platform_data *pdata);
#else
static inline int acpi_parse_aspt(struct resource *res, struct psp_platform_data *pdata)
{
	return -ENODEV;
}
#endif

#endif /* __LINUX_PSP_H */
