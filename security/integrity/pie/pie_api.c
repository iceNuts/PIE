/*
 * 39211306 Bill -> Homework
 *
 *	Implements must_measure, collect_measurement, store_measurement,
 *	and store_template.
 */

#include "pie.h"

#include <linux/module.h>

static const char *PIE_TEMPLATE_NAME = "pie";

/*
 * pie_store_template - store pie template measurements
 *
 * Calculate the hash of a template entry, add the template entry
 * to an ordered list of measurement entries maintained inside the kernel,
 * and also update the aggregate integrity value (maintained inside the
 * configured TPM PCR) over the hashes of the current list of measurement
 * entries.
 */

int pie_store_template(struct pie_template_entry *entry,
		       int violation, struct inode *inode)
{
	const char *op = "add_template_measure";
	const char *audit_cause = "hashing_error";
	int result;

	memset(entry->digest, 0, sizeof(entry->digest));
	entry->template_name = PIE_TEMPLATE_NAME;
	entry->template_len = sizeof(entry->template);

	if (!violation) {
		result = pie_calc_template_hash(entry->template_len,
						&entry->template,
						entry->digest);
		if (result < 0) {
			integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode,
					    entry->template_name, op,
					    audit_cause, result, 0);
			return result;
		}
	}
	result = pie_add_template_entry(entry, violation, op, inode);
	return result;
}

/*
 * pie_add_violation - add violation to measurement list.
 *
 * Violations are flagged in the measurement list with zero hash values.
 * By extending the PCR with 0xFF's instead of with zeroes, the PCR
 * value is invalidated.
 */

void pie_add_violation(struct inode *inode, const unsigned char *filename,
		       const char *op, const char *cause)
{
	struct pie_template_entry *entry;
	int violation = 1;
	int result;

	/* can overflow, only indicator */

	atomic_long_inc(&pie_htable.violations);

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		result = -ENOMEM;
		goto err_out;
	}
	memset(&entry->template, 0, sizeof(entry->template));
	strncpy(entry->template.file_name, filename, PIE_EVENT_NAME_LEN_MAX);
	result = pie_store_template(entry, violation, inode);
	if (result < 0)
		kfree(entry);

err_out:
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
			    op, cause, result, 0);
}

/**
 * pie_must_measure - measure decision based on policy.
*/

int pie_must_measure(struct pie_iint_cache *iint, struct inode *inode,
		     int mask, int function)
{
	int must_measure;

	if (iint->flags & PIE_MEASURED)
		return 1;

	must_measure = pie_match_policy(inode, function, mask);
	return must_measure ? 0 : -EACCES;
}

/*
 * pie_collect_measurement - collect file measurement
 *
 * Calculate the file hash, if it doesn't already exist,
 * storing the measurement and i_version in the iint.
 */

int pie_collect_measurement(struct pie_iint_cache *iint, struct file *file)
{
	int result = -EEXIST;

	if (!(iint->flags & PIE_MEASURED)) {
		u64 i_version = file->f_dentry->d_inode->i_version;

		memset(iint->digest, 0, PIE_DIGEST_SIZE);
		result = pie_calc_hash(file, iint->digest);
		if (!result)
			iint->version = i_version;
	}
	return result;
}

/*
 * pie_store_measurement - store file measurement
 *
 * Create an "pie" template and then store the template by calling
 * pie_store_template.
 */

void pie_store_measurement(struct pie_iint_cache *iint, struct file *file,
			   const unsigned char *filename)
{
	const char *op = "add_template_measure";
	const char *audit_cause = "ENOMEM";
	int result = -ENOMEM;
	struct inode *inode = file->f_dentry->d_inode;
	struct pie_template_entry *entry;
	int violation = 0;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
				    op, audit_cause, result, 0);
		return;
	}
	memset(&entry->template, 0, sizeof(entry->template));
	memcpy(entry->template.digest, iint->digest, PIE_DIGEST_SIZE);
	strncpy(entry->template.file_name, filename, PIE_EVENT_NAME_LEN_MAX);

	result = pie_store_template(entry, violation, inode);
	if (!result || result == -EEXIST)
		iint->flags |= PIE_MEASURED;
	if (result < 0)
		kfree(entry);
}
