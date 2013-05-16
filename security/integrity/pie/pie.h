/*
 * 39211306 Bill -> Declaration of global variables and functions
 */

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>

#ifndef __LINUX_PIE_H
#define __LINUX_PIE_H

enum pie_show_type { PIE_SHOW_BINARY, PIE_SHOW_ASCII };
enum tpm_pcrs { TPM_PCR0 = 0, TPM_PCR8 = 8 };

/* SHA1 Digest*/

#define PIE_HASH_BITS 9
#define PIE_MEASURE_HTABLE_SIZE (1 << PIE_HASH_BITS)

#define PIE_DIGEST_SIZE		20
#define PIE_EVENT_NAME_LEN_MAX	255

/* initialization */

extern int pie_initialized;
extern int pie_used_chip;
extern char *pie_hash;

/* pie inode template definition */

struct pie_template_data {
	u8 digest[PIE_DIGEST_SIZE];	/* SHA1 */
	char file_name[PIE_EVENT_NAME_LEN_MAX + 1];	/* name + \0 */
};

struct pie_template_entry {
	u8 digest[pie_DIGEST_SIZE];	/* SHA1 */
	int template_len;
	struct pie_template_data template;
	const char *template_name;
};

struct pie_queue_entry {
	struct pie_template_entry *entry;
	struct hlist_node hnext;	
	struct list_head later;		
};
extern struct list_head pie_measurements;	/* list of all measurements */

/* Internal PIE function definitions */
int pie_calc_hash(struct file *file, char *digest);
int pie_calc_template_hash(int template_len, void *template, char *digest);
int pie_calc_boot_aggregate(char *digest);
void pie_add_violation(struct inode *inode, const unsigned char *filename,
		       const char *op, const char *cause);

void pie_iintcache_init(void);
int pie_init(void);
void pie_cleanup(void);
int pie_fs_init(void);
void pie_fs_cleanup(void);
int pie_add_template_entry(struct pie_template_entry *entry, int violation,
			   const char *op, struct inode *inode);

/* declarations */
void integrity_audit_msg(int audit_msgno, struct inode *inode,
			 const unsigned char *fname, const char *op,
			 const char *cause, int result, int info);

/*
 * used to protect h_table and sha_table
 */
extern spinlock_t pie_queue_lock;

extern struct pie_h_table pie_htable;

struct pie_h_table {
	atomic_long_t len;	/* number of stored measurements in the list */
	atomic_long_t violations;
	struct hlist_head queue[PIE_MEASURE_HTABLE_SIZE];
};

/* iint cache flags */
#define PIE_MEASURED		1
#define PIE_IINT_DUMP_STACK	512

static inline unsigned long pie_hash_key(u8 *digest)
{
	return hash_long(*digest, PIE_HASH_BITS);
}


/* integrity data associated with an inode */
struct PIE_iint_cache {
	u64 version;		/* track inode changes */
	unsigned long flags;
	u8 digest[PIE_DIGEST_SIZE];
	struct mutex mutex;	/* protects: version, flags, digest */
	long readcount;		/* measured files readcount */
	long writecount;	/* measured files writecount */
	long opencount;		/* opens reference count */
	struct kref refcount;	/* pie_iint_cache reference count */
	struct rcu_head rcu;
};

/* PIE API function definitions */
int pie_must_measure(struct pie_iint_cache *iint, struct inode *inode,
		     int mask, int function);
int pie_collect_measurement(struct pie_iint_cache *iint, struct file *file);
void pie_store_measurement(struct pie_iint_cache *iint, struct file *file,
			   const unsigned char *filename);
int pie_store_template(struct pie_template_entry *entry, int violation,
		       struct inode *inode);
void pie_template_show(struct seq_file *m, void *e,
		       enum pie_show_type show);

/* pie policy related functions */
enum pie_hooks { PATH_CHECK = 1, FILE_MMAP, BPRM_CHECK };

int pie_match_policy(struct inode *inode, enum pie_hooks func, int mask);
void pie_init_policy(void);
void pie_update_policy(void);
int pie_parse_add_rule(char *);
void pie_delete_rules(void);

/* radix tree calls to lookup, insert, delete
 * integrity data associated with an inode.
 */
struct pie_iint_cache *pie_iint_insert(struct inode *inode);
struct pie_iint_cache *pie_iint_find_get(struct inode *inode);
struct pie_iint_cache *pie_iint_find_insert_get(struct inode *inode);
void pie_iint_delete(struct inode *inode);
void iint_free(struct kref *kref);
void iint_rcu_free(struct rcu_head *rcu);


/* LSM based policy rules require audit */
#ifdef CONFIG_PIE_LSM_RULES

#define security_filter_rule_init security_audit_rule_init
#define security_filter_rule_match security_audit_rule_match

#else

static inline int security_filter_rule_match(u32 secid, u32 field, u32 op,
					     void *lsmrule,
					     struct audit_context *actx)
{
	return -EINVAL;
}

static inline int security_filter_rule_init(u32 field, u32 op, char *rulestr,
					    void **lsmrule)
{
	return -EINVAL;
}

#endif 
#endif
