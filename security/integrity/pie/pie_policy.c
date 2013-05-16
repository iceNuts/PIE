/*
 * 39211306 Bill -> Homework rules to define verification strategy
 */

#include "pie.h"

#include <linux/module.h>
#include <linux/list.h>
#include <linux/security.h>
#include <linux/magic.h>
#include <linux/parser.h>

enum pie_action 
{ 
	UNKNOWN = -1, 
	DONT_MEASURE = 0, 
	MEASURE 
};

/* flags definitions */
#define PIE_FUNC 	0x0001
#define PIE_MASK 	0x0002
#define PIE_FSMAGIC	0x0004
#define PIE_UID		0x0008

#define MAX_LSM_RULES 6

enum lsm_rule_types 
{ 
	LSM_OBJ_USER, 
	LSM_OBJ_ROLE, 
	LSM_OBJ_TYPE,
	LSM_SUBJ_USER, 
	LSM_SUBJ_ROLE, 
	LSM_SUBJ_TYPE
};

struct pie_measure_rule_entry {
	
	struct list_head list;
	enum pie_action action;
	unsigned int flags;
	enum pie_hooks func;
	int mask;
	unsigned long fsmagic;
	uid_t uid;
	
	struct {
		/* LSM file metadata specific */
		void *rule;	
		/* audit type */
		int type;	
	} 
	lsm[MAX_LSM_RULES];
};

/*
 *	Dump security operations structure , used for hooks
 */
static struct pie_measure_rule_entry default_rules[] = 
{
	{.
		action = DONT_MEASURE,
		.fsmagic = PROC_SUPER_MAGIC,
		.flags = PIE_FSMAGIC
	},

	{
		.action = DONT_MEASURE,
		.fsmagic = SYSFS_MAGIC,
		.flags = PIE_FSMAGIC
	},

	{
		.action = DONT_MEASURE,
		.fsmagic = DEBUGFS_MAGIC,
		.flags = PIE_FSMAGIC
	},

	{
		.action = DONT_MEASURE,
		.fsmagic = TMPFS_MAGIC,
		.flags = PIE_FSMAGIC
	},

	{
		.action = DONT_MEASURE,
		.fsmagic = SECURITYFS_MAGIC,
		.flags = PIE_FSMAGIC
	},

	{
		.action = DONT_MEASURE,
		.fsmagic = SELINUX_MAGIC,
		.flags = PIE_FSMAGIC
	},
	
	{
		.action = MEASURE,
		.func = FILE_MMAP,
		.mask = MAY_EXEC,
	 	.flags = PIE_FUNC | PIE_MASK
	 },
	
	{
		.action = MEASURE,
		.func = BPRM_CHECK,
		.mask = MAY_EXEC,
	 	.flags = PIE_FUNC | PIE_MASK
	 },
	
	{
		.action = MEASURE,
		.func = PATH_CHECK,
		.mask = MAY_READ,
		.uid = 0,
	 	.flags = PIE_FUNC | PIE_MASK | PIE_UID
	 },
};

static LIST_HEAD(measure_default_rules);
static LIST_HEAD(measure_policy_rules);

static struct list_head *pie_measure;

static DEFINE_MUTEX(pie_measure_mutex);

static bool pie_use_tcb __initdata;

static int __init default_policy_setup(char *str)
{
	pie_use_tcb = 1;
	return 1;
}
__setup("pie_tcb", default_policy_setup);

/**
 * Returns true on rule match, false on failure.
 */
static bool pie_match_rules(struct pie_measure_rule_entry *rule,
			    struct inode *inode, enum pie_hooks func, int mask)
{
	struct task_struct *tsk = current;
	int i;

	if ((rule->flags & PIE_FUNC) && rule->func != func)
		return false;
	if ((rule->flags & PIE_MASK) && rule->mask != mask)
		return false;
	if ((rule->flags & PIE_FSMAGIC)
	    && rule->fsmagic != inode->i_sb->s_magic)
		return false;
	if ((rule->flags & PIE_UID) && rule->uid != tsk->cred->uid)
		return false;
	for (i = 0; i < MAX_LSM_RULES; i++) {
		int rc = 0;
		u32 osid, sid;

		if (!rule->lsm[i].rule)
			continue;

		switch (i) 
		{
			case LSM_OBJ_USER:
			case LSM_OBJ_ROLE:
			case LSM_OBJ_TYPE:
				security_inode_getsecid(inode, &osid);
				rc = security_filter_rule_match(osid,
							rule->lsm[i].type,
							Audit_equal,
							rule->lsm[i].rule,
							NULL);
				break;
			case LSM_SUBJ_USER:
			case LSM_SUBJ_ROLE:
			case LSM_SUBJ_TYPE:
			security_task_getsecid(tsk, &sid);
			rc = security_filter_rule_match(sid,
							rule->lsm[i].type,
							Audit_equal,
							rule->lsm[i].rule,
							NULL);
			default:
				break;
		}
		if (!rc)
			return false;
	}
	return true;
}

/**
 * Measure decision based on func/mask/fsmagic and LSM(subj/obj/type)
 */

int pie_match_policy(struct inode *inode, enum pie_hooks func, int mask)
{
	struct pie_measure_rule_entry *entry;

	list_for_each_entry(entry, pie_measure, list) {
		bool rc;

		rc = pie_match_rules(entry, inode, func, mask);
		if (rc)
			return entry->action;
	}
	return 0;
}

/**
 * pie_init_policy - initialize the default measure rules.
 */

void __init pie_init_policy(void)
{
	int i, entries;

	if (pie_use_tcb)
		entries = ARRAY_SIZE(default_rules);
	else
		entries = 0;

	for (i = 0; i < entries; i++)
		list_add_tail(&default_rules[i].list, &measure_default_rules);
	pie_measure = &measure_default_rules;
}

/**
 * Called on file .release to update the default rules with a complete new
 * policy.  
 */

void pie_update_policy(void)
{
	const char *op = "policy_update";
	const char *cause = "already exists";
	int result = 1;
	int audit_info = 0;

	if (pie_measure == &measure_default_rules) {
		pie_measure = &measure_policy_rules;
		cause = "complete";
		result = 0;
	}
	integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL,
			    NULL, op, cause, result, audit_info);
}

enum {
	Opt_err = -1,
	Opt_measure = 1, 
	Opt_dont_measure,
	Opt_obj_user, 
	Opt_obj_role, 
	Opt_obj_type,
	Opt_subj_user, 
	Opt_subj_role, 
	Opt_subj_type,
	Opt_func, 
	Opt_mask, 
	Opt_fsmagic, 
	Opt_uid
};

static match_table_t policy_tokens = 
{
	{Opt_measure, "measure"},
	{Opt_dont_measure, "dont_measure"},
	{Opt_obj_user, "obj_user=%s"},
	{Opt_obj_role, "obj_role=%s"},
	{Opt_obj_type, "obj_type=%s"},
	{Opt_subj_user, "subj_user=%s"},
	{Opt_subj_role, "subj_role=%s"},
	{Opt_subj_type, "subj_type=%s"},
	{Opt_func, "func=%s"},
	{Opt_mask, "mask=%s"},
	{Opt_fsmagic, "fsmagic=%s"},
	{Opt_uid, "uid=%s"},
	{Opt_err, NULL}
};

static int pie_lsm_rule_init(struct pie_measure_rule_entry *entry,
			     char *args, int lsm_rule, int audit_type)
{
	int result;

	entry->lsm[lsm_rule].type = audit_type;
	result = security_filter_rule_init(entry->lsm[lsm_rule].type,
					   Audit_equal, args,
					   &entry->lsm[lsm_rule].rule);
	if (!entry->lsm[lsm_rule].rule)
		return -EINVAL;
	return result;
}

static int pie_parse_rule(char *rule, struct pie_measure_rule_entry *entry)
{
	struct audit_buffer *ab;
	char *p;
	int result = 0;

	ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_INTEGRITY_RULE);

	entry->action = -1;
	while ((p = strsep(&rule, " \n")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		unsigned long lnum;

		if (result < 0)
			break;
		if (!*p)
			continue;
		token = match_token(p, policy_tokens, args);
		switch (token) {
		case Opt_measure:
			audit_log_format(ab, "%s ", "measure");
			entry->action = MEASURE;
			break;
		case Opt_dont_measure:
			audit_log_format(ab, "%s ", "dont_measure");
			entry->action = DONT_MEASURE;
			break;
		case Opt_func:
			audit_log_format(ab, "func=%s ", args[0].from);
			if (strcmp(args[0].from, "PATH_CHECK") == 0)
				entry->func = PATH_CHECK;
			else if (strcmp(args[0].from, "FILE_MMAP") == 0)
				entry->func = FILE_MMAP;
			else if (strcmp(args[0].from, "BPRM_CHECK") == 0)
				entry->func = BPRM_CHECK;
			else
				result = -EINVAL;
			if (!result)
				entry->flags |= PIE_FUNC;
			break;
		case Opt_mask:
			audit_log_format(ab, "mask=%s ", args[0].from);
			if ((strcmp(args[0].from, "MAY_EXEC")) == 0)
				entry->mask = MAY_EXEC;
			else if (strcmp(args[0].from, "MAY_WRITE") == 0)
				entry->mask = MAY_WRITE;
			else if (strcmp(args[0].from, "MAY_READ") == 0)
				entry->mask = MAY_READ;
			else if (strcmp(args[0].from, "MAY_APPEND") == 0)
				entry->mask = MAY_APPEND;
			else
				result = -EINVAL;
			if (!result)
				entry->flags |= PIE_MASK;
			break;
		case Opt_fsmagic:
			audit_log_format(ab, "fsmagic=%s ", args[0].from);
			result = strict_strtoul(args[0].from, 16,
						&entry->fsmagic);
			if (!result)
				entry->flags |= IMA_FSMAGIC;
			break;
		case Opt_uid:
			audit_log_format(ab, "uid=%s ", args[0].from);
			result = strict_strtoul(args[0].from, 10, &lnum);
			if (!result) {
				entry->uid = (uid_t) lnum;
				if (entry->uid != lnum)
					result = -EINVAL;
				else
					entry->flags |= PIE_UID;
			}
			break;
		case Opt_obj_user:
			audit_log_format(ab, "obj_user=%s ", args[0].from);
			result = pie_lsm_rule_init(entry, args[0].from,
						   LSM_OBJ_USER,
						   AUDIT_OBJ_USER);
			break;
		case Opt_obj_role:
			audit_log_format(ab, "obj_role=%s ", args[0].from);
			result = pie_lsm_rule_init(entry, args[0].from,
						   LSM_OBJ_ROLE,
						   AUDIT_OBJ_ROLE);
			break;
		case Opt_obj_type:
			audit_log_format(ab, "obj_type=%s ", args[0].from);
			result = pie_lsm_rule_init(entry, args[0].from,
						   LSM_OBJ_TYPE,
						   AUDIT_OBJ_TYPE);
			break;
		case Opt_subj_user:
			audit_log_format(ab, "subj_user=%s ", args[0].from);
			result = pie_lsm_rule_init(entry, args[0].from,
						   LSM_SUBJ_USER,
						   AUDIT_SUBJ_USER);
			break;
		case Opt_subj_role:
			audit_log_format(ab, "subj_role=%s ", args[0].from);
			result = pie_lsm_rule_init(entry, args[0].from,
						   LSM_SUBJ_ROLE,
						   AUDIT_SUBJ_ROLE);
			break;
		case Opt_subj_type:
			audit_log_format(ab, "subj_type=%s ", args[0].from);
			result = pie_lsm_rule_init(entry, args[0].from,
						   LSM_SUBJ_TYPE,
						   AUDIT_SUBJ_TYPE);
			break;
		case Opt_err:
			audit_log_format(ab, "UNKNOWN=%s ", p);
			break;
		}
	}
	if (entry->action == UNKNOWN)
		result = -EINVAL;

	audit_log_format(ab, "res=%d", !result ? 0 : 1);
	audit_log_end(ab);
	return result;
}

/**
 * Uses a mutex to protect the policy list from multiple concurrent writers.
 * Returns 0 on success, an error code on failure.
 */

int pie_parse_add_rule(char *rule)
{
	const char *op = "update_policy";
	struct pie_measure_rule_entry *entry;
	int result = 0;
	int audit_info = 0;

	if (pie_measure != &measure_default_rules) {
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL,
				    NULL, op, "already exists",
				    -EACCES, audit_info);
		return -EACCES;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL,
				    NULL, op, "-ENOMEM", -ENOMEM, audit_info);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&entry->list);

	result = pie_parse_rule(rule, entry);
	if (!result) {
		mutex_lock(&pie_measure_mutex);
		list_add_tail(&entry->list, &measure_policy_rules);
		mutex_unlock(&pie_measure_mutex);
	} else {
		kfree(entry);
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL,
				    NULL, op, "invalid policy", result,
				    audit_info);
	}
	return result;
}

/*Rule delete*/

void pie_delete_rules(void)
{
	struct pie_measure_rule_entry *entry, *tmp;

	mutex_lock(&pie_measure_mutex);
	
	list_for_each_entry_safe(entry, tmp, &measure_policy_rules, list) 
	{
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&pie_measure_mutex);
}
