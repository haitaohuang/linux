// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "ACPI: ASPT: " fmt
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_data/psp.h>

static int __init psp_validate_regs(const struct acpi_aspt_global_regs *gregs,
	const struct acpi_aspt_sev_mbox_regs *sevregs,
	const struct acpi_aspt_acpi_mbox_regs *acpiregs)
{
	u64 pfn;
	int idx;
	u64 regs[] = {
		gregs->feature_reg_addr,
		gregs->irq_en_reg_addr,
		gregs->irq_st_reg_addr,
		sevregs->cmd_resp_reg_addr,
		sevregs->cmd_buf_lo_reg_addr,
		sevregs->cmd_buf_hi_reg_addr,
		acpiregs->cmd_resp_reg_addr
	};
	pfn = regs[0] >> PAGE_SHIFT;
	for (idx = 1; idx < ARRAY_SIZE(regs); idx++) {
		if (regs[idx] >> PAGE_SHIFT != pfn)
			return -EINVAL;
	}
	return 0;
}

/**
 * acpi_parse_aspt - Parse ASPT table and return contained information
 * @res: will be filled with the address and size of the ASP register window
 * @pdata: will be filled with the register offsets parsed from the ASPT table
 */
int __init acpi_parse_aspt(struct resource *res, struct psp_platform_data *pdata)
{
	struct acpi_aspt_acpi_mbox_regs acpiregs = {};
	struct acpi_aspt_sev_mbox_regs sevregs = {};
	struct acpi_aspt_global_regs gregs = {};
	struct acpi_aspt_header *entry, *end;
	struct acpi_table_aspt *aspt;
	unsigned long base;
	acpi_status status;
	int err = 0;

	status = acpi_get_table(ACPI_SIG_ASPT, 0, (struct acpi_table_header **)&aspt);
	if (ACPI_FAILURE(status))
		return -ENODEV;
	if (aspt->header.revision != ASPT_REVISION_ID) {
		pr_err("unsupported table revision: %d\n", (int)aspt->header.revision);
		err = -ENODEV;
		goto exit;
	}
	entry = (struct acpi_aspt_header *)(aspt + 1);
	end = (struct acpi_aspt_header *)((void *)aspt + aspt->header.length);
	while (entry < end) {
		if (((void *)entry + entry->length) > (void *)end) {
			pr_err("error during parsing\n");
			err = -EINVAL;
			goto exit;
		}
		switch (entry->type) {
		case ACPI_ASPT_TYPE_GLOBAL_REGS:
			memcpy(&gregs, entry, entry->length);
			break;
		case ACPI_ASPT_TYPE_SEV_MBOX_REGS:
			memcpy(&sevregs, entry, entry->length);
			break;
		case ACPI_ASPT_TYPE_ACPI_MBOX_REGS:
			memcpy(&acpiregs, entry, entry->length);
			break;
		}
		entry = (struct acpi_aspt_header *)((void *)entry + entry->length);
	}
	if (!gregs.header.length || !sevregs.header.length || !acpiregs.header.length) {
		pr_err("missing ASPT table entry: %u %u %u\n", gregs.header.length,
			sevregs.header.length,
			acpiregs.header.length);
		err = -EINVAL;
		goto exit;
	}
	/* All registers are expected to be within the same page */
	err = psp_validate_regs(&gregs, &sevregs, &acpiregs);
	if (err) {
		pr_err("ASPT registers span multiple pages\n");
		goto exit;
	}

	base = ALIGN_DOWN(gregs.feature_reg_addr, PAGE_SIZE);
	*res = (struct resource)DEFINE_RES_MEM(base, PAGE_SIZE);

	pdata->sev_cmd_resp_reg = sevregs.cmd_resp_reg_addr & ~PAGE_MASK;
	pdata->sev_cmd_buf_lo_reg = sevregs.cmd_buf_lo_reg_addr & ~PAGE_MASK;
	pdata->sev_cmd_buf_hi_reg = sevregs.cmd_buf_hi_reg_addr & ~PAGE_MASK;
	pdata->feature_reg = gregs.feature_reg_addr & ~PAGE_MASK;
	pdata->irq_en_reg = gregs.irq_en_reg_addr & ~PAGE_MASK;
	pdata->irq_st_reg = gregs.irq_st_reg_addr & ~PAGE_MASK;
	pdata->mbox_irq_id = sevregs.mbox_irq_id;
	pdata->acpi_cmd_resp_reg = acpiregs.cmd_resp_reg_addr & ~PAGE_MASK;

exit:
	acpi_put_table((struct acpi_table_header *)aspt);
	return err;
}
