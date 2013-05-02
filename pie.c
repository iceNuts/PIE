#include "pie.h"

//Hooks

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

//security structure

static struct security_operations pie_ops = {
        .name =                         "pie",
 
        .ptrace_access_check            =               pie_ptrace_access_check,
        .ptrace_traceme                         =               pie_ptrace_traceme,
        .capget                                         =               pie_capget,
        .capset                                         =               pie_capset,
        .capable                                        =               pie_capable,
        .quotactl                                       =               pie_quotactl,
        .quota_on                                       =               pie_quota_on,
        .syslog                                         =               pie_syslog,
        .vm_enough_memory                       =               pie_vm_enough_memory,
 
        .netlink_send                           =               pie_netlink_send,
        .netlink_recv                           =               pie_netlink_recv,
 
        .bprm_set_creds                         =               pie_bprm_set_creds,
        .bprm_committing_creds          =               pie_bprm_committing_creds,
        .bprm_committed_creds           =               pie_bprm_committed_creds,
        .bprm_secureexec                        =               pie_bprm_secureexec,
 
        .sb_alloc_security                      =               pie_sb_alloc_security,
        .sb_free_security                       =               pie_sb_free_security,
        .sb_copy_data                           =               pie_sb_copy_data,
        .sb_remount                             =               pie_sb_remount,
        .sb_kern_mount                          =               pie_sb_kern_mount,
        .sb_show_options                        =               pie_sb_show_options,
        .sb_statfs                                      =               pie_sb_statfs,
        .sb_mount                                       =               pie_mount,
        .sb_umount                                      =               pie_umount,
        .sb_set_mnt_opts                        =               pie_set_mnt_opts,
        .sb_clone_mnt_opts                      =               pie_sb_clone_mnt_opts,
        .sb_parse_opts_str                      =               pie_parse_opts_str,
 
        .inode_alloc_security           =               pie_inode_alloc_security,
        .inode_free_security            =               pie_inode_free_security,
        .inode_init_security            =               pie_inode_init_security,
        .inode_create                           =               pie_inode_create,
        .inode_link                             =               pie_inode_link,
        .inode_unlink                           =               pie_inode_unlink,
        .inode_symlink                          =               pie_inode_symlink,
        .inode_mkdir                            =               pie_inode_mkdir,
        .inode_rmdir                            =               pie_inode_rmdir,
        .inode_mknod                            =               pie_inode_mknod,
        .inode_rename                           =               pie_inode_rename,
        .inode_readlink                         =               pie_inode_readlink,
        .inode_follow_link                      =               pie_inode_follow_link,
        .inode_permission                       =               pie_inode_permission,
        .inode_setattr                          =               pie_inode_setattr,
        .inode_getattr                          =               pie_inode_getattr,
        .inode_setxattr                         =               pie_inode_setxattr,
        .inode_post_setxattr            =               pie_inode_post_setxattr,
        .inode_getxattr                         =               pie_inode_getxattr,
        .inode_listxattr                        =               pie_inode_listxattr,
        .inode_removexattr                      =               pie_inode_removexattr,
        .inode_getsecurity                      =               pie_inode_getsecurity,
        .inode_setsecurity                      =               pie_inode_setsecurity,
        .inode_listsecurity             =               pie_inode_listsecurity,
        .inode_getsecid                         =               pie_inode_getsecid,
 
        .file_permission                        =               pie_file_permission,
        .file_alloc_security            =               pie_file_alloc_security,
        .file_free_security             =               pie_file_free_security,
        .file_ioctl                             =               pie_file_ioctl,
        .file_mmap                                      =               pie_file_mmap,
        .file_mprotect                          =               pie_file_mprotect,
        .file_lock                                      =               pie_file_lock,
        .file_fcntl                             =               pie_file_fcntl,
        .file_set_fowner                        =               pie_file_set_fowner,
        .file_send_sigiotask            =               pie_file_send_sigiotask,
        .file_receive                           =               pie_file_receive,
       
        .dentry_open                            =               pie_dentry_open,
 
        .task_create                            =               pie_task_create,
        .cred_alloc_blank                       =               pie_cred_alloc_blank,
        .cred_free                                      =               pie_cred_free,
        .cred_prepare                           =               pie_cred_prepare,
        .cred_transfer                          =               pie_cred_transfer,
        .kernel_act_as                          =               pie_kernel_act_as,
        .kernel_create_files_as         =               pie_kernel_create_files_as,
        .kernel_module_request          =               pie_kernel_module_request,
        .task_setpgid                           =               pie_task_setpgid,
        .task_getpgid                           =               pie_task_getpgid,
        .task_getsid                            =               pie_task_getsid,
        .task_getsecid                          =               pie_task_getsecid,
        .task_setnice                           =               pie_task_setnice,
        .task_setioprio                         =               pie_task_setioprio,
        .task_getioprio                         =               pie_task_getioprio,
        .task_setrlimit                         =               pie_task_setrlimit,
        .task_setscheduler                      =               pie_task_setscheduler,
        .task_getscheduler                      =               pie_task_getscheduler,
        .task_movememory                        =               pie_task_movememory,
        .task_kill                                      =               pie_task_kill,
        .task_wait                                      =               pie_task_wait,
        .task_to_inode                          =               pie_task_to_inode,
 
        .ipc_permission                         =               pie_ipc_permission,
        .ipc_getsecid                           =               pie_ipc_getsecid,
 
        .msg_msg_alloc_security         =               pie_msg_msg_alloc_security,
        .msg_msg_free_security          =               pie_msg_msg_free_security,
 
        .msg_queue_alloc_security       =               pie_msg_queue_alloc_security,
        .msg_queue_free_security        =               pie_msg_queue_free_security,
        .msg_queue_associate            =               pie_msg_queue_associate,
        .msg_queue_msgctl                       =               pie_msg_queue_msgctl,
        .msg_queue_msgsnd                       =               pie_msg_queue_msgsnd,
        .msg_queue_msgrcv                       =               pie_msg_queue_msgrcv,
 
        .shm_alloc_security             =               pie_shm_alloc_security,
        .shm_free_security                      =               pie_shm_free_security,
        .shm_associate                          =               pie_shm_associate,
        .shm_shmctl                             =               pie_shm_shmctl,
        .shm_shmat                                      =               pie_shm_shmat,
 
        .sem_alloc_security             =               pie_sem_alloc_security,
        .sem_free_security                      =               pie_sem_free_security,
        .sem_associate                          =               pie_sem_associate,
        .sem_semctl                             =               pie_sem_semctl,
        .sem_semop                                      =               pie_sem_semop,
 
        .d_instantiate                          =               pie_d_instantiate,
 
        .getprocattr                            =               pie_getprocattr,
        .setprocattr                            =               pie_setprocattr,
 
        .secid_to_secctx                        =               pie_secid_to_secctx,
        .secctx_to_secid                        =               pie_secctx_to_secid,
        .release_secctx                         =               pie_release_secctx,
        .inode_notifysecctx             =               pie_inode_notifysecctx,
        .inode_setsecctx                        =               pie_inode_setsecctx,
        .inode_getsecctx                        =               pie_inode_getsecctx,
 
        .unix_stream_connect            =               pie_socket_unix_stream_connect,
        .unix_may_send                          =               pie_socket_unix_may_send,
 
        .socket_create                          =               pie_socket_create,
        .socket_post_create             =               pie_socket_post_create,
        .socket_bind                            =               pie_socket_bind,
        .socket_connect                         =               pie_socket_connect,
        .socket_listen                          =               pie_socket_listen,
        .socket_accept                          =               pie_socket_accept,
        .socket_sendmsg                         =               pie_socket_sendmsg,
        .socket_recvmsg                         =               pie_socket_recvmsg,
        .socket_getsockname             =               pie_socket_getsockname,
        .socket_getpeername                     =               pie_socket_getpeername,
        .socket_getsockopt                      =               pie_socket_getsockopt,
        .socket_setsockopt                      =               pie_socket_setsockopt,
        .socket_shutdown                        =               pie_socket_shutdown,
        .socket_sock_rcv_skb            =               pie_socket_sock_rcv_skb,
        .socket_getpeersec_stream       =               pie_socket_getpeersec_stream,
        .socket_getpeersec_dgram        =               pie_socket_getpeersec_dgram,
        .sk_alloc_security                      =               pie_sk_alloc_security,
        .sk_free_security                       =               pie_sk_free_security,
        .sk_clone_security                      =               pie_sk_clone_security,
        .sk_getsecid                            =               pie_sk_getsecid,
        .sock_graft                             =               pie_sock_graft,
        .inet_conn_request                      =               pie_inet_conn_request,
        .inet_csk_clone                         =               pie_inet_csk_clone,
        .inet_conn_established          =               pie_inet_conn_established,
        .secmark_relabel_packet         =               pie_secmark_relabel_packet,
        .secmark_refcount_inc           =               pie_secmark_refcount_inc,
        .secmark_refcount_dec           =               pie_secmark_refcount_dec,
        .req_classify_flow                      =               pie_req_classify_flow,
        .tun_dev_create                         =               pie_tun_dev_create,
        .tun_dev_post_create            =               pie_tun_dev_post_create,
        .tun_dev_attach                         =               pie_tun_dev_attach,
};

//init
static __init int pie_init(void)
{
	if (register_security(&pie_ops)) 
	{
		panic(KERN_INFO "Failed to register PIE module\n");
	}

	//Start Atomic Cache list & TPM things
    
    printk(KERN_ALERT "PIE started\n");
	
    return 0;
}

static void __exit pie_exit(void)
{
	//Free Up Space & delete files

	printk(KERN_INFO "PIE Unloaded\n");
}

module_init(pie_init);
module_exit(pie_exit);







