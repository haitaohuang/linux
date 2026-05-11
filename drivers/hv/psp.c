// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "psp: " fmt
#include <linux/platform_data/psp.h>
#include <linux/platform_device.h>
#include <linux/iopoll.h>
#include <linux/irq.h>
#include <linux/acpi.h>
#include <linux/msi.h>
#include <asm/apic.h>
#include <asm/hypervisor.h>
#include <asm/irqdomain.h>

#define PSP_ACPI_CMDID_SHIFT 16
#define PSP_ACPI_STATUS_SHIFT 26
#define PSP_ACPI_STATUS_MASK GENMASK(30, 26)
#define PSP_ACPI_RESPONSE_BIT BIT(31)
#define PSP_ACPI_VECTOR_MASK GENMASK(7, 0)
#define PSP_ACPI_DEST_MODE_SHIFT 9
#define PSP_ACPI_MBOX_IRQID_SHIFT 10
#define PSP_ACPI_IRQ_EN_BIT BIT(0)
#define PSP_ACPI_IRQ_EN_MBOX_IRQID_SHIFT 10

#define PSP_CMD_DELAY_US 2
#define PSP_CMD_TIMEOUT_US 10000

enum ASP_CMDID {
ASP_CMDID_PART1  = 0x82,
ASP_CMDID_PART2  = 0x83,
ASP_CMDID_PART3  = 0x84,
ASP_CMDID_IRQ_EN = 0x85,
};

enum ASP_CMD_STATUS {
ASP_CMD_STATUS_SUCCESS = 0x0,
ASP_CMD_STATUS_INVALID_CMD = 0x1,
ASP_CMD_STATUS_INVALID_PARAM = 0x2,
ASP_CMD_STATUS_INVALID_FW_STATE = 0x3,
ASP_CMD_STATUS_FAILURE = 0x1F,
};

struct psp_irq_data {
void __iomem *base;
u8 mbox_irq_id;
int acpi_cmd_resp_reg;
};
static struct psp_irq_data pspirqd;

static int psp_sync_cmd(void __iomem *reg, u8 cmd, u16 data)
{
u32 val;
int err;

val  = data;
val |= cmd << PSP_ACPI_CMDID_SHIFT;
writel(val, reg);
err = readl_poll_timeout_atomic(reg, val, val & PSP_ACPI_RESPONSE_BIT, PSP_CMD_DELAY_US, PSP_CMD_TIMEOUT_US);
if (err)
return err;

return (val & PSP_ACPI_STATUS_MASK) >> PSP_ACPI_STATUS_SHIFT;
}

static int psp_set_irq_enable(struct psp_irq_data *data, bool irq_en)
{
void __iomem *reg = data->base + data->acpi_cmd_resp_reg;
u16 val = 0;
int err;

if (data->mbox_irq_id > 63)
return -EINVAL;

val  = irq_en ? PSP_ACPI_IRQ_EN_BIT : 0;
val |= data->mbox_irq_id << PSP_ACPI_IRQ_EN_MBOX_IRQID_SHIFT;
err = psp_sync_cmd(reg, ASP_CMDID_IRQ_EN, val);
if (err != ASP_CMD_STATUS_SUCCESS) {
pr_err("ASP_CMDID_IRQ_EN failed: %d\n", err);
return -EIO;
}

return 0;
}

static int psp_configure_irq(struct psp_irq_data *data, const struct msi_msg *msg)
{
void __iomem *reg = data->base + data->acpi_cmd_resp_reg;
unsigned int vector, apicid;
u16 part1, part2, part3;
bool dest_mode_logical;
int err;

if (data->mbox_irq_id > 63)
return -EINVAL;

vector = msg->arch_data.vector;
apicid = msg->arch_addr_lo.virt_destid_8_14 << 8 |  msg->arch_addr_lo.destid_0_7;
dest_mode_logical = msg->arch_addr_lo.dest_mode_logical;

part1  = apicid;
part2  = apicid >> 16;
part3  = vector & PSP_ACPI_VECTOR_MASK;
part3 |= dest_mode_logical << PSP_ACPI_DEST_MODE_SHIFT;
part3 |= data->mbox_irq_id << PSP_ACPI_MBOX_IRQID_SHIFT;

err = psp_sync_cmd(reg, ASP_CMDID_PART1, part1);
if (err != ASP_CMD_STATUS_SUCCESS) {
pr_err("ASP_CMDID_PART1 failed: %d\n", err);
return -EIO;
}
err = psp_sync_cmd(reg, ASP_CMDID_PART2, part2);
if (err != ASP_CMD_STATUS_SUCCESS) {
pr_err("ASP_CMDID_PART2 failed: %d\n", err);
return -EIO;
}
err = psp_sync_cmd(reg, ASP_CMDID_PART3, part3);
if (err != ASP_CMD_STATUS_SUCCESS) {
pr_err("ASP_CMDID_PART3 failed: %d\n", err);
return -EIO;
}

return 0;
}

static void psp_irq_unmask(struct irq_data *data)
{
struct psp_irq_data *pspirqd = irq_data_get_irq_chip_data(data);

psp_set_irq_enable(pspirqd, true);
}

static void psp_irq_mask(struct irq_data *data)
{
struct psp_irq_data *pspirqd = irq_data_get_irq_chip_data(data);

psp_set_irq_enable(pspirqd, false);
}

static void psp_irq_write_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
struct psp_irq_data *pspirqd = irq_data_get_irq_chip_data(data);
int err = psp_configure_irq(pspirqd, msg);
WARN_ON_ONCE(err);
}

static const struct msi_domain_template psp_msi_template = {
.chip = {
.name = "PSP-MSI",
.irq_mask = psp_irq_mask,
.irq_unmask = psp_irq_unmask,
.irq_write_msi_msg = psp_irq_write_msi_msg,
.flags = IRQCHIP_ONESHOT_SAFE,
},
.info = {
.flags = MSI_FLAG_FREE_MSI_DESCS|
 MSI_FLAG_DEV_SYSFS|
 MSI_FLAG_ACTIVATE_EARLY|
 MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS,
.bus_token = DOMAIN_BUS_PCI_DEVICE_MSI,
}
};

static int psp_init_irq_data(const struct resource *reg, const struct psp_platform_data *pdata)
{
void __iomem *base;

base = ioremap(reg->start, resource_size(reg));
if (!base)
return -ENOMEM;

pspirqd.mbox_irq_id = pdata->mbox_irq_id;
pspirqd.acpi_cmd_resp_reg = pdata->acpi_cmd_resp_reg;
pspirqd.base = base;

return 0;
}

int psp_alloc_irq(struct platform_device *pdev)
{
struct device *dev = &pdev->dev;
int virq;
int err;

if (!msi_create_device_irq_domain(dev, MSI_DEFAULT_DOMAIN, &psp_msi_template, 1, NULL, &pspirqd)) {
dev_err(dev, "failed to ceate MSI domain\n");
return -EINVAL;
}
err = msi_domain_alloc_irqs_range(dev, MSI_DEFAULT_DOMAIN, 0, 0);
if (err) {
dev_err(dev, "failed to allocate MSI: %d\n", err);
return err;
}
virq = msi_get_virq(dev, 0);
if (!virq) {
dev_err(dev, "failed to get virq\n");
return -ENOENT;
}
return virq;
}
EXPORT_SYMBOL_GPL(psp_alloc_irq);

void psp_free_irq(struct platform_device *pdev)
{
msi_domain_free_irqs_all_locked(&pdev->dev, MSI_DEFAULT_DOMAIN);
}
EXPORT_SYMBOL_GPL(psp_free_irq);

static int __init psp_init_platform_device(void)
{
struct psp_platform_data pdata = {};
struct platform_device *psp_device;
struct resource res[1];
int err;

/*
 * The ACPI PSP interface is mutually exclusive with the PCIe interface,
 * but there is no reason to use the ACPI interface over the PCIe one.
 * Restrict probing ACPI PSP to platforms known to only expose the ACPI
 * interface, which at this time is SNP-host capable Hyper-V VMs.
 */
if (!hypervisor_is_type(X86_HYPER_MS_HYPERV))
return -ENODEV;

err = acpi_parse_aspt(&res[0], &pdata);
if (err)
return err;
psp_device = platform_device_alloc("psp", PLATFORM_DEVID_NONE);
if (!psp_device) {
pr_err("failed to alloc platform device\n");
return -ENOMEM;
}
dev_set_msi_domain(&psp_device->dev, x86_pci_msi_default_domain);
err = psp_init_irq_data(&res[0], &pdata);
if (err)
goto err;
err = platform_device_add_resources(psp_device, res, 1);
if (err)
goto err;
err = platform_device_add_data(psp_device, &pdata, sizeof(pdata));
if (err)
goto err;
err = platform_device_add(psp_device);
if (err)
goto err;
return 0;

err:
platform_device_put(psp_device);
return err;
}
device_initcall(psp_init_platform_device);

MODULE_LICENSE("GPL");
