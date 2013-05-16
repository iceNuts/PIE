/*
 * 39211306 Bill -> Homework init and cleanup
 */

#include "pie.h" 
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/err.h>


/* name for boot aggregate entry */
static const char *boot_aggregate_name = "boot_aggregate";
int pie_used_chip;

/* Add the boot aggregate to the PIE measurement list and extend
 * the PCR register.
 */

static void __init pie_add_boot_aggregate(void)
{
	struct pie_template_entry *entry;
	const char *op = "add_boot_aggregate";
	const char *audit_cause = "ENOMEM";
	int result = -ENOMEM;
	int violation = 1;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		goto err_out;

	memset(&entry->template, 0, sizeof(entry->template));
	strncpy(entry->template.file_name, boot_aggregate_name,
		PIE_EVENT_NAME_LEN_MAX);
	if (pie_used_chip) {
		violation = 0;
		result = pie_calc_boot_aggregate(entry->template.digest);
		if (result < 0) {
			audit_cause = "hashing_error";
			kfree(entry);
			goto err_out;
		}
	}

	result = pie_store_template(entry, violation, NULL);
	if (result < 0)
		kfree(entry);
	return;

err_out:
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, NULL, boot_aggregate_name, op,
			    audit_cause, result, 0);
}

int __init pie_init(void)
{
	u8  [PIE_DIGEST_SIZE];
	int rc;

	pie_used_chip = 0;
	rc = tpm_pcr_read(TPM_ANY_NUM, 0, pcr_i);
	if (rc == 0)
		pie_used_chip = 1;

	if (!pie_used_chip)
		pr_info("No TPM chip found, activating TPM-bypass!\n");

	pie_add_boot_aggregate();	/* boot aggregate must be first entry */
	pie_init_policy();

	return pie_fs_init();
}

void __exit pie_cleanup(void)
{
	pie_fs_cleanup();
}
