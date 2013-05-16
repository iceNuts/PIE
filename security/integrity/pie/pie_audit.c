/*
 * 39211306 Bill -> Homework
 * 	Audit calls for the integrity subsystem
 */

#include "pie.h"

#include <linux/fs.h>
#include <linux/audit.h>

static int pie_audit;

#ifdef CONFIG_PIE_AUDIT

/* pie_audit_setup - enable informational auditing messages */

static int __init pie_audit_setup(char *str)
{
	unsigned long audit;

	if (!strict_strtoul(str, 0, &audit))
		pie_audit = audit ? 1 : 0;
	return 1;
}
__setup("pie_audit=", pie_audit_setup);

#endif

void integrity_audit_msg(int audit_msgno, struct inode *inode,
			 const unsigned char *fname, const char *op,
			 const char *cause, int result, int audit_info)
{
	struct audit_buffer *ab;

	if (!pie_audit && audit_info == 1) /* Skip informational messages */
		return;

	ab = audit_log_start(current->audit_context, GFP_KERNEL, audit_msgno);
	audit_log_format(ab, "integrity: pid=%d uid=%u auid=%u ses=%u",
			 current->pid, current_cred()->uid,
			 audit_get_loginuid(current),
			 audit_get_sessionid(current));
	audit_log_task_context(ab);
	audit_log_format(ab, " op=");
	audit_log_string(ab, op);
	audit_log_format(ab, " cause=");
	audit_log_string(ab, cause);
	audit_log_format(ab, " comm=");
	audit_log_untrustedstring(ab, current->comm);
	if (fname) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, fname);
	}
	if (inode)
		audit_log_format(ab, " dev=%s ino=%lu",
				 inode->i_sb->s_id, inode->i_ino);
	audit_log_format(ab, " res=%d", !result ? 0 : 1);
	audit_log_end(ab);
}
