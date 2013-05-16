/*
 * 39211306 Bill -> queue for  PIE, we treat it as a cache
 */

/* 
 * mutex protects atomicity of extending measurement list
 * and extending the TPM PCR aggregate. Since tpm_extend can take
 * long (and the tpm driver uses a mutex), we can't use the spinlock.
 */

#include "pie.h"
#include <linux/rculist.h>
#include <linux/module.h>

/* list of all measurements */

LIST_HEAD(pie_measurements);	

/* key: inode (before secure-hashing a file) */

struct pie_h_table pie_htable = {
	.queue[0 ... PIE_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT
	.len = ATOMIC_LONG_INIT(0),
	.violations = ATOMIC_LONG_INIT(0),
};

static DEFINE_MUTEX(pie_extend_list_mutex);

/* lookup up the digest value in the hash table, and return the entry */

static struct pie_queue_entry *pie_lookup_digest_entry(u8 *digest_value)
{
	struct pie_queue_entry *qe, *ret = NULL;
	unsigned int key;
	struct hlist_node *pos;
	int rc;

	key = pie_hash_key(digest_value);
	rcu_read_lock();
	hlist_for_each_entry_rcu(qe, pos, &pie_htable.queue[key], hnext) {
		rc = memcmp(qe->entry->digest, digest_value, pie_DIGEST_SIZE);
		if (rc == 0) {
			ret = qe;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

/* 
 * pie_add_template_entry helper function:
 * - Add template entry to measurement list and hash table.
 *
 * (Called with pie_extend_list_mutex held.)
 */
static int pie_add_digest_entry(struct pie_template_entry *entry)
{
	struct pie_queue_entry *qe;
	unsigned int key;

	qe = kmalloc(sizeof(*qe), GFP_KERNEL);
	if (qe == NULL) {
		pr_err("OUT OF MEMORY ERROR creating queue entry.\n");
		return -ENOMEM;
	}
	qe->entry = entry;

	INIT_LIST_HEAD(&qe->later);
	list_add_tail_rcu(&qe->later, &pie_measurements);

	atomic_long_inc(&pie_htable.len);
	key = pie_hash_key(entry->digest);
	hlist_add_head_rcu(&qe->hnext, &pie_htable.queue[key]);
	return 0;
}

static int pie_pcr_extend(const u8 *hash)
{
	int result = 0;

	if (!pie_used_chip)
		return result;

	result = tpm_pcr_extend(TPM_ANY_NUM, CONFIG_pie_MEASURE_PCR_IDX, hash);
	if (result != 0)
		pr_err("Error Communicating to TPM chip\n");
	return result;
}

/* 
 * Add template entry to the measurement list and hash table,
 * and extend the pcr.
 */
int pie_add_template_entry(struct pie_template_entry *entry, int violation,
			   const char *op, struct inode *inode)
{
	const char *audit_cause = "hash_added";
	int audit_info = 1;
	int result = 0;
	u8 digest[PIE_DIGEST_SIZE];

	mutex_lock(&pie_extend_list_mutex);
	if (!violation) {
		memcpy(digest, entry->digest, sizeof digest);
		
		if (pie_lookup_digest_entry(digest)) 
		{
			audit_cause = "hash_exists";
			result = -EEXIST;
			goto out;
		}
	}

	result = pie_add_digest_entry(entry);
	if (result < 0) 
	{
		audit_cause = "ENOMEM";
		audit_info = 0;
		goto out;
	}

	if (violation)		/* invalidate pcr */
		memset(digest, 0xff, sizeof digest);

	result = pie_pcr_extend(digest);
	if (result != 0) 
	{
		audit_cause = "TPM error";
		audit_info = 0;
	}

out:
	mutex_unlock(&pie_extend_list_mutex);
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode,
			    entry->template.file_name,
			    op, audit_cause, result, audit_info);
	return result;
}
