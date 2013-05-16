/*
 * 39211306 Bill -> Homework hook implementation & cache
 */


#include "pie.h" 
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>


RADIX_TREE(pie_iint_store, GFP_ATOMIC);
DEFINE_SPINLOCK(pie_iint_lock);

#define pie_iint_delete pieuy_inode_free

static struct kmem_cache *iint_cache __read_mostly;

/* 
 *	pie_iint_find_get - return the iint associated with an inode
 *
 *  pie_iint_find_get gets a reference to the iint. 
 */

struct pie_iint_cache *pie_iint_find_get(struct inode *inode)
{
	struct pie_iint_cache *iint;

	rcu_read_lock();
	iint = radix_tree_lookup(&pie_iint_store, (unsigned long)inode);
	if (!iint)
		goto out;
	kref_get(&iint->refcount);
out:
	rcu_read_unlock();
	return iint;
}

/* Allocate memory for the iint associated with the inode
 * from the iint_cache slab, initialize the iint, and
 * insert it into the radix tree.
 */

struct pie_iint_cache *pie_iint_insert(struct inode *inode)
{
	struct pie_iint_cache *iint = NULL;
	int rc = 0;

	if (!pie_initialized)
		return iint;
	iint = kmem_cache_alloc(iint_cache, GFP_NOFS);
	if (!iint)
		return iint;

	rc = radix_tree_preload(GFP_NOFS);
	if (rc < 0)
		goto out;

	spin_lock(&pie_iint_lock);
	rc = radix_tree_insert(&pie_iint_store, (unsigned long)inode, iint);
	spin_unlock(&pie_iint_lock);

out:
	if (rc < 0) {
		kmem_cache_free(iint_cache, iint);
		if (rc == -EEXIST) {
			spin_lock(&pie_iint_lock);
			iint = radix_tree_lookup(&pie_iint_store,
						 (unsigned long)inode);
			spin_unlock(&pie_iint_lock);
		} else
			iint = NULL;
	}
	radix_tree_preload_end();
	return iint;
}

/**
 * pie_inode_alloc - allocate an iint associated with an inode
 *
 * Return 0 on success, 1 on failure.
 */

int pie_inode_alloc(struct inode *inode)
{
	struct pie_iint_cache *iint;

	if (!pie_initialized)
		return 0;

	iint = pie_iint_insert(inode);
	if (!iint)
		return 1;
	return 0;
}

/*  get the iint associated with an inode
 *  Return the iint.
 */
struct pie_iint_cache *pie_iint_find_insert_get(struct inode *inode)
{
	struct pie_iint_cache *iint = NULL;

	iint = pie_iint_find_get(inode);
	if (iint)
		return iint;

	iint = pie_iint_insert(inode);
	if (iint)
		kref_get(&iint->refcount);

	return iint;
}
EXPORT_SYMBOL_GPL(pie_iint_find_insert_get);

/* iint_free - called when the iint refcount goes to zero */
void iint_free(struct kref *kref)
{
	struct pie_iint_cache *iint = container_of(kref, struct pie_iint_cache,
						   refcount);
	iint->version = 0;
	iint->flags = 0UL;
	if (iint->readcount != 0) {
		printk(KERN_INFO "%s: readcount: %ld\n", __FUNCTION__,
		       iint->readcount);
		iint->readcount = 0;
	}
	if (iint->writecount != 0) {
		printk(KERN_INFO "%s: writecount: %ld\n", __FUNCTION__,
		       iint->writecount);
		iint->writecount = 0;
	}
	if (iint->opencount != 0) {
		printk(KERN_INFO "%s: opencount: %ld\n", __FUNCTION__,
		       iint->opencount);
		iint->opencount = 0;
	}
	kref_set(&iint->refcount, 1);
	kmem_cache_free(iint_cache, iint);
}

void iint_rcu_free(struct rcu_head *rcu_head)
{
	struct pie_iint_cache *iint = container_of(rcu_head,
						   struct pie_iint_cache, rcu);
	kref_put(&iint->refcount, iint_free);
}

/**
 * called on integrity_inode_free
 * Free the integrity information(iint) associated with an inode.
 */

void pie_iint_delete(struct inode *inode)
{
	struct pie_iint_cache *iint;

	if (!pie_initialized)
		return;
	spin_lock(&pie_iint_lock);
	iint = radix_tree_delete(&pie_iint_store, (unsigned long)inode);
	spin_unlock(&pie_iint_lock);
	if (iint)
		call_rcu(&iint->rcu, iint_rcu_free);
}

static void init_once(void *foo)
{
	struct pie_iint_cache *iint = foo;

	memset(iint, 0, sizeof *iint);
	iint->version = 0;
	iint->flags = 0UL;
	mutex_init(&iint->mutex);
	iint->readcount = 0;
	iint->writecount = 0;
	iint->opencount = 0;
	kref_set(&iint->refcount, 1);
}

void __init pie_iintcache_init(void)
{
	iint_cache =
	    kmem_cache_create("iint_cache", sizeof(struct pie_iint_cache), 0,
			      SLAB_PANIC, init_once);
}
