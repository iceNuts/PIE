/*
 * 39211306 Bill -> Homework lsm implementation
 */

#include "pie.h"

#include <linux/module.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/mman.h>


int pie_initialized;

char *pie_hash = "sha1";

static int __init hash_setup(char *str)
{
	if (strncmp(str, "md5", 3) == 0)
		pie_hash = "md5";
	return 1;
}
__setup("pie_hash=", hash_setup);

/*
 *	Get notified when the file has been changed	
 */

void pie_file_free(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct pie_iint_cache *iint;

	if (!pie_initialized || !S_ISREG(inode->i_mode))
		return;
	iint = pie_iint_find_get(inode);
	if (!iint)
		return;

	mutex_lock(&iint->mutex);
	if (iint->opencount <= 0) 
	{
		printk(KERN_INFO
		       "%s: %s open/free imbalance (r:%ld w:%ld o:%ld f:%ld)\n",
		       __FUNCTION__, file->f_dentry->d_name.name,
		       iint->readcount, iint->writecount,
		       iint->opencount, atomic_long_read(&file->f_count));
		if (!(iint->flags & PIE_IINT_DUMP_STACK)) {
			dump_stack();
			iint->flags |= PIE_IINT_DUMP_STACK;
		}
	}
	iint->opencount--;

	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		iint->readcount--;

	if (file->f_mode & FMODE_WRITE) {
		iint->writecount--;
		if (iint->writecount == 0) {
			if (iint->version != inode->i_version)
				iint->flags &= ~IMA_MEASURED;
		}
	}
	mutex_unlock(&iint->mutex);
	kref_put(&iint->refcount, iint_free);
}

/* 
 *	TOMTOU error -> to solve synchronization problem
 */
enum iint_pcr_error { TOMTOU, OPEN_WRITERS };

static void pie_read_write_check(enum iint_pcr_error error,
				 struct pie_iint_cache *iint,
				 struct inode *inode,
				 const unsigned char *filename)
{
	switch (error) {
	case TOMTOU:
		if (iint->readcount > 0)
			pie_add_violation(inode, filename, "invalid_pcr",
					  "ToMToU");
		break;
	case OPEN_WRITERS:
		if (iint->writecount > 0)
			pie_add_violation(inode, filename, "invalid_pcr",
					  "open_writers");
		break;
	}
}

static int get_path_measurement(struct pie_iint_cache *iint, struct file *file,
				const unsigned char *filename)
{
	int rc = 0;

	iint->opencount++;
	iint->readcount++;

	rc = pie_collect_measurement(iint, file);
	if (!rc)
		pie_store_measurement(iint, file, filename);
	return rc;
}

static void pie_update_counts(struct pie_iint_cache *iint, int mask)
{
	iint->opencount++;
	if ((mask & MAY_WRITE) || (mask == 0))
		iint->writecount++;
	else if (mask & (MAY_READ | MAY_EXEC))
		iint->readcount++;
}

/**
 * invalidate the PCR for measured files:
 * 	- Opening a file for write when already open for read,
 *	  results in a time of measure, time of use (ToMToU) error.
 *	- Opening a file for read when already open for write,
 * 	  could result in a file measurement error.
 */
int pie_path_check(struct path *path, int mask, int update_counts)
{
	struct inode *inode = path->dentry->d_inode;
	struct pie_iint_cache *iint;
	struct file *file = NULL;
	int rc;

	if (!pie_initialized || !S_ISREG(inode->i_mode))
		return 0;
	iint = pie_iint_find_insert_get(inode);
	if (!iint)
		return 0;

	mutex_lock(&iint->mutex);
	if (update_counts)
		pie_update_counts(iint, mask);

	rc = pie_must_measure(iint, inode, MAY_READ, PATH_CHECK);
	if (rc < 0)
		goto out;

	if ((mask & MAY_WRITE) || (mask == 0))
		pie_read_write_check(TOMTOU, iint, inode,
				     path->dentry->d_name.name);

	if ((mask & (MAY_WRITE | MAY_READ | MAY_EXEC)) != MAY_READ)
		goto out;

	pie_read_write_check(OPEN_WRITERS, iint, inode,
			     path->dentry->d_name.name);
	if (!(iint->flags & PIE_MEASURED)) {
		struct dentry *dentry = dget(path->dentry);
		struct vfsmount *mnt = mntget(path->mnt);

		file = dentry_open(dentry, mnt, O_RDONLY | O_LARGEFILE,
				   current_cred());
		if (IS_ERR(file)) {
			int audit_info = 0;

			integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode,
					    dentry->d_name.name,
					    "add_measurement",
					    "dentry_open failed",
					    1, audit_info);
			file = NULL;
			goto out;
		}
		rc = get_path_measurement(iint, file, dentry->d_name.name);
	}
out:
	mutex_unlock(&iint->mutex);
	if (file)
		fput(file);
	kref_put(&iint->refcount, iint_free);
	return 0;
}
EXPORT_SYMBOL_GPL(pie_path_check);

/*
 * Process Integrity Mensurement Core function
 */

static int process_measurement(struct file *file, const unsigned char *filename,
			       int mask, int function)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct pie_iint_cache *iint;
	int rc;

	if (!pie_initialized || !S_ISREG(inode->i_mode))
		return 0;
	iint = pie_iint_find_insert_get(inode);
	if (!iint)
		return -ENOMEM;

	mutex_lock(&iint->mutex);
	rc = pie_must_measure(iint, inode, mask, function);
	if (rc != 0)
		goto out;

	rc = pie_collect_measurement(iint, file);
	if (!rc)
		pie_store_measurement(iint, file, filename);
out:
	mutex_unlock(&iint->mutex);
	kref_put(&iint->refcount, iint_free);
	return rc;
}

/*
 * pie_counts_put - decrement file counts
 */

void pie_counts_put(struct path *path, int mask)
{
	struct inode *inode = path->dentry->d_inode;
	struct pie_iint_cache *iint;

	if (!pie_initialized || !inode || !S_ISREG(inode->i_mode))
		return;
	iint = pie_iint_find_insert_get(inode);
	if (!iint)
		return;

	mutex_lock(&iint->mutex);
	iint->opencount--;
	if ((mask & MAY_WRITE) || (mask == 0))
		iint->writecount--;
	else if (mask & (MAY_READ | MAY_EXEC))
		iint->readcount--;
	mutex_unlock(&iint->mutex);

	kref_put(&iint->refcount, iint_free);
}

/*
 *  pie_counts_get - increment file counts
 */

void pie_counts_get(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct pie_iint_cache *iint;

	if (!pie_initialized || !S_ISREG(inode->i_mode))
		return;
	iint = pie_iint_find_insert_get(inode);
	if (!iint)
		return;
	mutex_lock(&iint->mutex);
	iint->opencount++;
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		iint->readcount++;

	if (file->f_mode & FMODE_WRITE)
		iint->writecount++;
	mutex_unlock(&iint->mutex);

	kref_put(&iint->refcount, iint_free);
}
EXPORT_SYMBOL_GPL(pie_counts_get);

/**
 * pie_file_mmap - based on policy, collect/store measurement.
 * Return 0 on success, an error code on failure.
 */

int pie_file_mmap(struct file *file, unsigned long prot)
{
	int rc;

	if (!file)
		return 0;
	if (prot & PROT_EXEC)
		rc = process_measurement(file, file->f_dentry->d_name.name,
					 MAY_EXEC, FILE_MMAP);
	return 0;
}

/**
 * pie_bprm_check - based on policy, collect/store measurement.
 */
int pie_bprm_check(struct linux_binprm *bprm)
{
	int rc;

	rc = process_measurement(bprm->file, bprm->filename,
				 MAY_EXEC, BPRM_CHECK);
	return 0;
}

static int __init init_pie(void)
{
	int error;

	pie_iintcache_init();
	error = pie_init();
	pie_initialized = 1;
	return error;
}

static void __exit cleanup_pie(void)
{
	pie_cleanup();
}

late_initcall(init_pie);	/* Start PIE after the TPM is available */

MODULE_DESCRIPTION("Integrity Measurement Architecture");
MODULE_LICENSE("GPL");
