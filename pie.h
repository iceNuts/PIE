//important includes for security module


#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/module.h>       /* Needed by all modules */
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>   /* for local_port_range[] */
#include <net/tcp.h>    /* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>  /* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>   /* for Unix socket types */
#include <net/af_unix.h>  /* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/user_namespace.h>

//basic definition
#define MODULE_NAME "pie"

//module info
MODULE_AUTHOR("billzeng");
MODULE_DESCRIPTION("Process Integrity Evaluator");
MODULE_LICENSE("GPL");
MODULE_VERSION("alpha");

//globals
extern struct security_operations *security_ops;

#define DIGEST_SIZE 20


//pie_cache

//A list as sha1 key-value pair hash table
//Use RCU mechanism to gurantee write-read collision

//Mutex lock vs Spin lock ? The previous would make others sleep then waken up by alert
//But the latter would keep others request for control over and over again.
//Mutex is fit for pcr extend as it takes a long time.

//Definitions
struct  pie_table
{
    /* data */
    struct list_head list;
};

struct pie_table_entry
{
    /* data */
    u8 *digest;
    struct list_head latter;
};


//Lookup function
static int pie_table_lookup(u8 *digest);
//Add entry
int pie_add_entry(u8 *digest);



//pie_tpm
#define TPM_CHIP_NUM TPM_ANY_NUM
//Assume pcr 12 as storage slot
#define TPM_PCR_NUM 12


static int pie_pcr_extend(const u8 *hash);
static int pie_pcr_read(u8 *res_buf);
static int pie_calc_hash(struct file *file, char *digest);
static int pie_calc_list_hash(void *list, char *digest);


















