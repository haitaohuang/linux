// SPDX-License-Identifier: GPL-2.0-only

#include <linux/platform_data/psp.h>
#include <linux/platform_device.h>
#include <asm/hypervisor.h>


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

	err = acpi_parse_aspt(res, &pdata);
	if (err)
		return err;
	psp_device = platform_device_alloc("psp", PLATFORM_DEVID_NONE);
	if (!psp_device) {
		pr_err("failed to alloc platform device\n");
		return -ENOMEM;
	}
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
