/*
 * 39211306 Bill -> Homework File system security options
 */

#include "pie.h"

#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>


static int valid_policy = 1;
#define TMPBUFLEN 12

static ssize_t pie_show_htable_value(char __user *buf, size_t count,
				     loff_t *ppos, atomic_long_t *val)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t len;

	len = scnprintf(tmpbuf, TMPBUFLEN, "%li\n", atomic_long_read(val));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}


static ssize_t pie_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos)
{
	return pie_show_htable_value(buf, count, ppos, &pie_htable.violations);
}

static const struct file_operations pie_htable_violations_ops = {
	.read = pie_show_htable_violations
};

static ssize_t pie_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	return pie_show_htable_value(buf, count, ppos, &pie_htable.len);

}

static const struct file_operations pie_measurements_count_ops = {
	.read = pie_show_measurements_count
};

/* returns pointer to hlist_node */

static void *pie_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct pie_queue_entry *qe;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(qe, &pie_measurements, later) {
		if (!l--) {
			rcu_read_unlock();
			return qe;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *pie_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct pie_queue_entry *qe = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */

	rcu_read_lock();
	qe = list_entry_rcu(qe->later.next,
			    struct pie_queue_entry, later);
	rcu_read_unlock();
	(*pos)++;

	return (&qe->later == &pie_measurements) ? NULL : qe;
}

static void pie_measurements_stop(struct seq_file *m, void *v)
{
}

static void pie_putc(struct seq_file *m, void *data, int datalen)
{
	while (datalen--)
		seq_putc(m, *(char *)data++);
}

/* 
 * format:
 *       32bit-le=pcr#
 *       char[20]=template digest
 *       32bit-le=template name size
 *       char[n]=template name
 *       eventdata[n]=template specific data
 */

static int pie_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct pie_queue_entry *qe = v;
	struct pie_template_entry *e;
	int namelen;
	u32 pcr = CONFIG_PIE_MEASURE_PCR_IDX;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	/*
	 * 1st: PCRIndex
	 * PCR used is always the same (config option) in
	 * little-endian format
	 */
	pie_putc(m, &pcr, sizeof pcr);

	/* 2nd: template digest */
	pie_putc(m, e->digest, PIE_DIGEST_SIZE);

	/* 3rd: template name size */
	namelen = strlen(e->template_name);
	pie_putc(m, &namelen, sizeof namelen);

	/* 4th:  template name */
	pie_putc(m, (void *)e->template_name, namelen);

	/* 5th:  template specific data */
	pie_template_show(m, (struct pie_template_data *)&e->template,
			  PIE_SHOW_BINARY);
	return 0;
}

static const struct seq_operations pie_measurments_seqops = {
	.start = pie_measurements_start,
	.next = pie_measurements_next,
	.stop = pie_measurements_stop,
	.show = pie_measurements_show
};

static int pie_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pie_measurments_seqops);
}

static const struct file_operations pie_measurements_ops = {
	.open = pie_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static void pie_print_digest(struct seq_file *m, u8 *digest)
{
	int i;

	for (i = 0; i < PIE_DIGEST_SIZE; i++)
		seq_printf(m, "%02x", *(digest + i));
}

void pie_template_show(struct seq_file *m, void *e, enum pie_show_type show)
{
	struct pie_template_data *entry = e;
	int namelen;

	switch (show) {
	case PIE_SHOW_ASCII:
		pie_print_digest(m, entry->digest);
		seq_printf(m, " %s\n", entry->file_name);
		break;
	case PIE_SHOW_BINARY:
		pie_putc(m, entry->digest, PIE_DIGEST_SIZE);

		namelen = strlen(entry->file_name);
		pie_putc(m, &namelen, sizeof namelen);
		pie_putc(m, entry->file_name, namelen);
	
	default:
		break;
	}
}

/* print in ascii */
static int pie_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct pie_queue_entry *qe = v;
	struct pie_template_entry *e;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	/* 1st: PCR used (config option) */
	seq_printf(m, "%2d ", CONFIG_PIE_MEASURE_PCR_IDX);

	/* 2nd: SHA1 template hash */
	pie_print_digest(m, e->digest);

	/* 3th:  template name */
	seq_printf(m, " %s ", e->template_name);

	/* 4th:  template specific data */
	pie_template_show(m, (struct pie_template_data *)&e->template,
			  PIE_SHOW_ASCII);
	return 0;
}

static const struct seq_operations pie_ascii_measurements_seqops = {
	.start = pie_measurements_start,
	.next = pie_measurements_next,
	.stop = pie_measurements_stop,
	.show = pie_ascii_measurements_show
};

static int pie_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pie_ascii_measurements_seqops);
}

static const struct file_operations pie_ascii_measurements_ops = {
	.open = pie_ascii_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static ssize_t pie_write_policy(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data;
	int rc;

	if (datalen >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	data = kmalloc(datalen + 1, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (copy_from_user(data, buf, datalen)) {
		kfree(data);
		return -EFAULT;
	}
	*(data + datalen) = '\0';
	rc = pie_parse_add_rule(data);
	if (rc < 0) {
		datalen = -EINVAL;
		valid_policy = 0;
	}

	kfree(data);
	return datalen;
}

static struct dentry *pie_dir;
static struct dentry *binary_runtime_measurements;
static struct dentry *ascii_runtime_measurements;
static struct dentry *runtime_measurements_count;
static struct dentry *violations;
static struct dentry *pie_policy;

static atomic_t policy_opencount = ATOMIC_INIT(1);

/*
 * pie_open_policy: sequentialize access to the policy file
 */

int pie_open_policy(struct inode * inode, struct file * filp)
{
	/* No point in being allowed to open it if you aren't going to write */
	if (!(filp->f_flags & O_WRONLY))
		return -EACCES;
	if (atomic_dec_and_test(&policy_opencount))
		return 0;
	return -EBUSY;
}

/*
 * pie_release_policy - start using the new measure policy rules.
 */
static int pie_release_policy(struct inode *inode, struct file *file)
{
	if (!valid_policy) {
		pie_delete_rules();
		valid_policy = 1;
		atomic_set(&policy_opencount, 1);
		return 0;
	}
	pie_update_policy();
	securityfs_remove(pie_policy);
	pie_policy = NULL;
	return 0;
}

static const struct file_operations pie_measure_policy_ops = {
	.open = pie_open_policy,
	.write = pie_write_policy,
	.release = pie_release_policy
};

int __init pie_fs_init(void)
{
	pie_dir = securityfs_create_dir("pie", NULL);
	if (IS_ERR(pie_dir))
		return -1;

	binary_runtime_measurements =
	    securityfs_create_file("binary_runtime_measurements",
				   S_IRUSR | S_IRGRP, pie_dir, NULL,
				   &pie_measurements_ops);
	if (IS_ERR(binary_runtime_measurements))
		goto out;

	ascii_runtime_measurements =
	    securityfs_create_file("ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP, pie_dir, NULL,
				   &pie_ascii_measurements_ops);
	if (IS_ERR(ascii_runtime_measurements))
		goto out;

	runtime_measurements_count =
	    securityfs_create_file("runtime_measurements_count",
				   S_IRUSR | S_IRGRP, pie_dir, NULL,
				   &pie_measurements_count_ops);
	if (IS_ERR(runtime_measurements_count))
		goto out;

	violations =
	    securityfs_create_file("violations", S_IRUSR | S_IRGRP,
				   pie_dir, NULL, &pie_htable_violations_ops);
	if (IS_ERR(violations))
		goto out;

	pie_policy = securityfs_create_file("policy",
					    S_IWUSR,
					    pie_dir, NULL,
					    &pie_measure_policy_ops);
	if (IS_ERR(pie_policy))
		goto out;

	return 0;
out:
	securityfs_remove(runtime_measurements_count);
	securityfs_remove(ascii_runtime_measurements);
	securityfs_remove(binary_runtime_measurements);
	securityfs_remove(pie_dir);
	securityfs_remove(pie_policy);
	return -1;
}

void __exit pie_fs_cleanup(void)
{
	securityfs_remove(violations);
	securityfs_remove(runtime_measurements_count);
	securityfs_remove(ascii_runtime_measurements);
	securityfs_remove(binary_runtime_measurements);
	securityfs_remove(pie_dir);
	securityfs_remove(pie_policy);
}
