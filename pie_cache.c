#include "pie_cache.h"

//Definitions
struct  pie_table
{
    /* data */
    u8 *digest;
    struct list_head list;
};

LIST_HEAD(cache_head);

static DEFINE_MUTEX(cache_head_mutex);

//Lookup function
static int pie_table_lookup(u8 *digest)
{   
    struct pie_table_entry *entry;
    int ret = 0, rc = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(entry, cache_head, list){
        rc = memcmp(entry -> digest, digest, DIGEST_SIZE);
        if(0 == rc)
        {
            ret = 1;
            break;
        }
    }
    rcu_read_unlock();
    return ret;
}

//Add entry
int pie_add_entry(u8 *digest)
{
    struct pie_table_entry *entry;
    entry = kmalloc(sizeof(entry), GFP_KERNEL);
    int ret;

    if(NULL == entry)
    {
        pr_err("PIE_ADD_ENTRY: Memory Allocation Error");
        return -ENOMEM;
    }

    entry->digest = digest;
    INIT_LIST_HEAD(&entry -> later);
    list_add_tail_rcu( &entry->latter, &cache_head );

    mutex_lock(&cache_head_mutex);
    ret = pie_tpm_extend(digest);
    mutex_unlock(&cache_head_mutex);

    return ret;
}




