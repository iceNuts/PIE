#include "pie.h"

static int pie_ptrace_access_check(struct task_struct *child,
                     unsigned int mode)
{
    return 0;
}

static int pie_ptrace_traceme(struct task_struct *parent)
{
    return 0;
}

static int pie_capget(struct task_struct *target, kernel_cap_t *effective,
              kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    return 0;
}

static int pie_capset(struct cred *new, const struct cred *old,
              const kernel_cap_t *effective,
              const kernel_cap_t *inheritable,
              const kernel_cap_t *permitted)
{
    return 0;
}

static int pie_capable(struct task_struct *tsk, const struct cred *cred,
               struct user_namespace *ns, int cap, int audit)
{
    return 0;
}

static int pie_quotactl(int cmds, int type, int id, struct super_block *sb)
{
    return 0;
}

static int pie_quota_on(struct dentry *dentry)
{
    return 0;
}

static int pie_syslog(int type)
{
    return 0;
}


static int pie_vm_enough_memory(struct mm_struct *mm, long pages)
{
    return 0;
}

/* binprm security operations */

static int pie_bprm_set_creds(struct linux_binprm *bprm)
{
    return 0;
}

static int pie_bprm_secureexec(struct linux_binprm *bprm)
{
    return 0;
}

static void pie_bprm_committing_creds(struct linux_binprm *bprm)
{
    
}

static void pie_bprm_committed_creds(struct linux_binprm *bprm)
{
    
}

static int pie_sb_alloc_security(struct super_block *sb)
{
    return 0;
}

static void pie_sb_free_security(struct super_block *sb)
{

}

static int pie_sb_copy_data(char *orig, char *copy)
{
    return 0;
}

static int pie_sb_remount(struct super_block *sb, void *data)
{
    return 0;
}

static int pie_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
    return 0;
}

static int pie_sb_statfs(struct dentry *dentry)
{
    return 0;
}

static int pie_mount(char *dev_name, struct path *path, char *type, unsigned long flags, void *data)
{
    return 0;
}

static int pie_umount(struct vfsmount *mnt, int flags)
{
    return 0;
}


/* inode security operations */

static int pie_inode_alloc_security(struct inode *inode)
{
    return 0;
}

static void pie_inode_free_security(struct inode *inode)
{

}

static int pie_inode_init_security(struct inode *inode, struct inode *dir,
                       const struct qstr *qstr, char **name,
                       void **value, size_t *len)
{
    return 0;
}

static int pie_inode_create(struct inode *dir, struct dentry *dentry, int mask)
{
    printk(KERN_ALERT "You shall not pass!\n");
    return -EACCES;
    return 0;
}

static int pie_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    return 0;
}

static int pie_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    return 0;
}

static int pie_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
    return 0;
}

static int pie_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
    return 0;
}

static int pie_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    return 0;
}

static int pie_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    return 0;
}

static int pie_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                struct inode *new_inode, struct dentry *new_dentry)
{
    return 0;
}

static int pie_inode_readlink(struct dentry *dentry)
{
    return 0;
}

static int pie_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
    return 0;
}

static int pie_inode_permission(struct inode *inode, int mask, unsigned flags)
{
    return 0;
}

static void pie_sb_clone_mnt_opts(const struct super_block *oldsb,
                    struct super_block *newsb)
{

}

static int pie_file_set_fowner(struct file *file)
{
    return 0;
}

static int pie_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
    return 0;
}

static int pie_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
    return 0;
}

static int pie_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
    return 0;
}

static int pie_inode_setotherxattr(struct dentry *dentry, const char *name)
{
    return 0;
}

static int pie_inode_setxattr(struct dentry *dentry, const char *name,
                  const void *value, size_t size, int flags)
{
    return 0;
}

static void pie_inode_post_setxattr(struct dentry *dentry, const char *name,
                    const void *value, size_t size,
                    int flags)
{
    
}

static int pie_inode_getxattr(struct dentry *dentry, const char *name)
{
    return 0;
}

static int pie_inode_listxattr(struct dentry *dentry)
{
    return 0;
}

static int pie_inode_removexattr(struct dentry *dentry, const char *name)
{
    return 0;
}

static int pie_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
    return 0;
}

static int pie_inode_setsecurity(struct inode *inode, const char *name,
                     const void *value, size_t size, int flags)
{
    return 0;
}

static int pie_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
    return 0;
}

static void pie_inode_getsecid(const struct inode *inode, u32 *secid)
{
    
}


/* file security operations */

static int pie_revalidate_file_permission(struct file *file, int mask)
{
    return 0;
}

static int pie_file_permission(struct file *file, int mask)
{
    return 0;
}

static int pie_file_alloc_security(struct file *file)
{
    return 0;
}

static void pie_file_free_security(struct file *file)
{

}

static int pie_file_ioctl(struct file *file, unsigned int cmd,
                  unsigned long arg)
{
    return 0;
}

static int file_map_prot_check(struct file *file, unsigned long prot, int shared)
{
    return 0;
}

static int pie_file_mmap(struct file *file, unsigned long reqprot,
                 unsigned long prot, unsigned long flags,
                 unsigned long addr, unsigned long addr_only)
{
    return 0;
}

static int pie_file_mprotect(struct vm_area_struct *vma,
                 unsigned long reqprot,
                 unsigned long prot)
{
    return 0;
}

static int pie_file_lock(struct file *file, unsigned int cmd)
{
    return 0;
}

static int pie_file_fcntl(struct file *file, unsigned int cmd,
                  unsigned long arg)
{
    return 0;
}

static int pie_file_send_sigiotask(struct task_struct *tsk,
                       struct fown_struct *fown, int signum)
{
    return 0;
}

static int pie_file_receive(struct file *file)
{
    return 0;
}

static int pie_dentry_open(struct file *file, const struct cred *cred)
{
    return 0;
}


/* task security operations */

static int pie_task_create(unsigned long clone_flags)
{
    return 0;
}

static int pie_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
    return 0;
}

static void pie_cred_free(struct cred *cred)
{
    
}

static int pie_cred_prepare(struct cred *new, const struct cred *old,
                gfp_t gfp)
{
    return 0;
}

static void pie_cred_transfer(struct cred *new, const struct cred *old)
{

}

static int pie_kernel_act_as(struct cred *new, u32 secid)
{
    return 0;
}

static int pie_kernel_create_files_as(struct cred *new, struct inode *inode)
{
    return 0;
}

static int pie_kernel_module_request(char *kmod_name)
{
    return 0;
}

static int pie_task_setpgid(struct task_struct *p, pid_t pgid)
{
    return 0;
}

static int pie_task_getpgid(struct task_struct *p)
{
    return 0;
}

static int pie_task_getsid(struct task_struct *p)
{
    return 0;
}

static void pie_task_getsecid(struct task_struct *p, u32 *secid)
{
    
}

static int pie_task_setnice(struct task_struct *p, int nice)
{
    return 0;
}

static int pie_task_setioprio(struct task_struct *p, int ioprio)
{
    return 0;
}

static int pie_task_getioprio(struct task_struct *p)
{
    return 0;
}

static int pie_task_setrlimit(struct task_struct *p, unsigned int resource,
        struct rlimit *new_rlim)
{
    return 0;
}

static int pie_task_setscheduler(struct task_struct *p)
{
    return 0;
}

static int pie_task_getscheduler(struct task_struct *p)
{
    return 0;
}

static int pie_task_movememory(struct task_struct *p)
{
    return 0;
}

static int pie_task_kill(struct task_struct *p, struct siginfo *info,
                int sig, u32 secid)
{
    return 0;
}

static int pie_task_wait(struct task_struct *p)
{
    return 0;
}

static void pie_task_to_inode(struct task_struct *p,
                  struct inode *inode)
{

}


/* socket security operations */

static int pie_socket_create(int family, int type,
                 int protocol, int kern)
{
    return 0;
}

static int pie_socket_post_create(struct socket *sock, int family,
                      int type, int protocol, int kern)
{
    return 0;
}

static int pie_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
    return 0;
}

static int pie_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    return 0;
}

static int pie_socket_listen(struct socket *sock, int backlog)
{
    return 0;
}

static int pie_socket_accept(struct socket *sock, struct socket *newsock)
{
    return 0;
}

static int pie_socket_sendmsg(struct socket *sock, struct msghdr *msg,
                  int size)
{
    return 0;
}

static int pie_socket_recvmsg(struct socket *sock, struct msghdr *msg,
                  int size, int flags)
{
    return 0;
}

static int pie_socket_getsockname(struct socket *sock)
{
    return 0;
}

static int pie_socket_getpeername(struct socket *sock)
{
    return 0;
}

static int pie_socket_setsockopt(struct socket *sock, int level, int optname)
{
    return 0;
}

static int pie_socket_getsockopt(struct socket *sock, int level,
                     int optname)
{
    return 0;
}

static int pie_socket_shutdown(struct socket *sock, int how)
{
    return 0;
}

static int pie_socket_unix_stream_connect(struct sock *sock,
                          struct sock *other,
                          struct sock *newsk)
{
    return 0;
}

static int pie_sb_show_options(struct seq_file *m, struct super_block *sb)
{
    return 0;
}

static int pie_set_mnt_opts(struct super_block *sb,
                struct security_mnt_opts *opts)
{
    return 0;
}

static int pie_socket_unix_may_send(struct socket *sock,
                    struct socket *other)
{
    return 0;
}

static int pie_sock_rcv_skb_compat(struct sock *sk, struct sk_buff *skb,
                       u16 family)
{
    return 0;
}

static int pie_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

static int pie_socket_getpeersec_stream(struct socket *sock, char __user *optval,
                        int __user *optlen, unsigned len)
{
    return 0;
}

static int pie_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
    return 0;
}

static int pie_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
    return 0;
}

static void pie_sk_free_security(struct sock *sk)
{
    
}

static void pie_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
    
}

static void pie_sk_getsecid(struct sock *sk, u32 *secid)
{
    
}

static void pie_sock_graft(struct sock *sk, struct socket *parent)
{
    
}

static int pie_inet_conn_request(struct sock *sk, struct sk_buff *skb,
                     struct request_sock *req)
{
    return 0;
}

static void pie_inet_csk_clone(struct sock *newsk,
                   const struct request_sock *req)
{
    
}

static void pie_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
    
}

static int pie_secmark_relabel_packet(u32 sid)
{
    return 0;
}

static void pie_secmark_refcount_inc(void)
{

}

static void pie_secmark_refcount_dec(void)
{
    
}

static void pie_req_classify_flow(const struct request_sock *req,
                      struct flowi *fl)
{
    
}

static int pie_tun_dev_create(void)
{
    return 0;
}

static void pie_tun_dev_post_create(struct sock *sk)
{
    
}

static int pie_tun_dev_attach(struct sock *sk)
{
    return 0;
}

static int pie_nlmsg_perm(struct sock *sk, struct sk_buff *skb)
{
    return 0;
}


static int pie_netlink_send(struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

static int pie_netlink_recv(struct sk_buff *skb, int capability)
{
    return 0;
}

static int ipc_alloc_security(struct task_struct *task,
                  struct kern_ipc_perm *perm,
                  u16 sclass)
{
    return 0;
}

static void ipc_free_security(struct kern_ipc_perm *perm)
{
    
}

static int msg_msg_alloc_security(struct msg_msg *msg)
{
    return 0;
}

static void msg_msg_free_security(struct msg_msg *msg)
{
    
}

static int ipc_has_perm(struct kern_ipc_perm *ipc_perms,
            u32 perms)
{
    return 0;
}

static int pie_msg_msg_alloc_security(struct msg_msg *msg)
{
    return 0;
}

static void pie_msg_msg_free_security(struct msg_msg *msg)
{
    
}

static int pie_msg_queue_alloc_security(struct msg_queue *msq)
{
    return 0;
}

static void pie_msg_queue_free_security(struct msg_queue *msq)
{
    
}

static int pie_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
    return 0;
}

static int pie_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
    return 0;
}

static int pie_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
    return 0;
}

static int pie_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
                    struct task_struct *target,
                    long type, int mode)
{
    return 0;
}


/* Shared Memory security operations */

static int pie_shm_alloc_security(struct shmid_kernel *shp)
{
    return 0;
}

static void pie_shm_free_security(struct shmid_kernel *shp)
{
    
}

static int pie_shm_associate(struct shmid_kernel *shp, int shmflg)
{
    return 0;
}

static int pie_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
    return 0;
}

static int pie_shm_shmat(struct shmid_kernel *shp,
                 char __user *shmaddr, int shmflg)
{
    return 0;
}


/* Semaphore security operations */

static int pie_sem_alloc_security(struct sem_array *sma)
{
return 0;
}

static void pie_sem_free_security(struct sem_array *sma)
{

}

static int pie_sem_associate(struct sem_array *sma, int semflg)
{
    return 0;
}

static int pie_sem_semctl(struct sem_array *sma, int cmd)
{
    return 0;
}

static int pie_sem_semop(struct sem_array *sma,
                 struct sembuf *sops, unsigned nsops, int alter)
{
    return 0;
}

static int pie_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
    return 0;
}

static void pie_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{

}

static void pie_d_instantiate(struct dentry *dentry, struct inode *inode)
{
    
}

static int pie_getprocattr(struct task_struct *p,
                   char *name, char **value)
{
    return 0;
}

static int pie_setprocattr(struct task_struct *p,
                   char *name, void *value, size_t size)
{
    return 0;
}

static int pie_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
    return 0;
}

static int pie_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
    return 0;
}

static void pie_release_secctx(char *secdata, u32 seclen)
{
    
}

static int pie_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
    return 0;
}

static int pie_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
    return 0;
}

static int pie_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
    return 0;
}
