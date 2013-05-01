#include "pie.h"

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







