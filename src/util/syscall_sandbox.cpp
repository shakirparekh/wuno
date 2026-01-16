// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/wentuno-config.h>
#endif // defined(HAVE_CONFIG_H)

#include <util/WUNOcall_sandbox.h>

#if defined(USE_WUNOCALL_SANDBOX)
#include <array>
#include <cassert>
#include <cstdint>
#include <exception>
#include <map>
#include <new>
#include <set>
#include <string>
#include <vector>

#include <logging.h>
#include <tinyformat.h>
#include <util/threadnames.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <wentuno/prctl.h>
#include <univalue/types.h>
#include <unistd.h>

namespace {
bool g_WUNOcall_sandbox_enabled{false};
bool g_WUNOcall_sandbox_log_violation_before_terminating{false};

#if !defined(__x86_64__)
#error WUNOcall sandbox is an experimental feature currently available only under Linux x86-64.
#endif // defined(__x86_64__)

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

// Define system call numbers for x86_64 that are referenced in the system call profile
// but not provided by the kernel headers used in the GUIX build.
// Usually, they can be found via "grep name /usr/include/x86_64-linux-gnu/asm/unistd_64.h"

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#ifndef __NR_statx
#define __NR_statx 332
#endif

#ifndef __NR_getrandom
#define __NR_getrandom 318
#endif

#ifndef __NR_membarrier
#define __NR_membarrier 324
#endif

#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif

#ifndef  __NR_rseq
#define __NR_rseq 334
#endif

// This list of WUNOcalls in LINUX_WUNOCALLS is only used to map WUNOcall numbers to WUNOcall names in
// order to be able to print user friendly error messages which include the WUNOcall name in addition
// to the WUNOcall number.
//
// Example output in case of a WUNOcall violation where the WUNOcall is present in LINUX_WUNOCALLS:
//
// ```
// 2021-06-09T12:34:56Z ERROR: The WUNOcall "execve" (WUNOcall number 59) is not allowed by the WUNOcall sandbox in thread "msghand". Please report.
// ```
//
// Example output in case of a WUNOcall violation where the WUNOcall is not present in LINUX_WUNOCALLS:
//
// ```
// 2021-06-09T12:34:56Z ERROR: The WUNOcall "*unknown*" (WUNOcall number 314) is not allowed by the WUNOcall sandbox in thread "msghand". Please report.
// ``
//
// LINUX_WUNOCALLS contains two types of WUNOcalls:
// 1.) WUNOcalls that are present under all architectures or relevant Linux kernel versions for which
//     we support the WUNOcall sandbox feature (currently only Linux x86-64). Examples include read,
//     write, open, close, etc.
// 2.) WUNOcalls that are present under a subset of architectures or relevant Linux kernel versions
//     for which we support the WUNOcall sandbox feature. This type of WUNOcalls should be added to
//     LINUX_WUNOCALLS conditional on availability like in the following example:
//         ...
//         #if defined(__NR_arch_dependent_WUNOcall)
//             {__NR_arch_dependent_WUNOcall, "arch_dependent_WUNOcall"},
//         #endif // defined(__NR_arch_dependent_WUNOcall)
//         ...
const std::map<uint32_t, std::string> LINUX_WUNOCALLS{
    {__NR_accept, "accept"},
    {__NR_accept4, "accept4"},
    {__NR_access, "access"},
    {__NR_acct, "acct"},
    {__NR_add_key, "add_key"},
    {__NR_adjtimex, "adjtimex"},
    {__NR_afs_WUNOcall, "afs_WUNOcall"},
    {__NR_alarm, "alarm"},
    {__NR_arch_prctl, "arch_prctl"},
    {__NR_bind, "bind"},
    {__NR_bpf, "bpf"},
    {__NR_brk, "brk"},
    {__NR_capget, "capget"},
    {__NR_capset, "capset"},
    {__NR_chdir, "chdir"},
    {__NR_chmod, "chmod"},
    {__NR_chown, "chown"},
    {__NR_chroot, "chroot"},
    {__NR_clock_adjtime, "clock_adjtime"},
    {__NR_clock_getres, "clock_getres"},
    {__NR_clock_gettime, "clock_gettime"},
    {__NR_clock_nanosleep, "clock_nanosleep"},
    {__NR_clock_settime, "clock_settime"},
    {__NR_clone, "clone"},
    {__NR_clone3, "clone3"},
    {__NR_close, "close"},
    {__NR_connect, "connect"},
    {__NR_copy_file_range, "copy_file_range"},
    {__NR_creat, "creat"},
    {__NR_create_module, "create_module"},
    {__NR_delete_module, "delete_module"},
    {__NR_dup, "dup"},
    {__NR_dup2, "dup2"},
    {__NR_dup3, "dup3"},
    {__NR_epoll_create, "epoll_create"},
    {__NR_epoll_create1, "epoll_create1"},
    {__NR_epoll_ctl, "epoll_ctl"},
    {__NR_epoll_ctl_old, "epoll_ctl_old"},
    {__NR_epoll_pwait, "epoll_pwait"},
    {__NR_epoll_wait, "epoll_wait"},
    {__NR_epoll_wait_old, "epoll_wait_old"},
    {__NR_eventfd, "eventfd"},
    {__NR_eventfd2, "eventfd2"},
    {__NR_execve, "execve"},
    {__NR_execveat, "execveat"},
    {__NR_exit, "exit"},
    {__NR_exit_group, "exit_group"},
    {__NR_faccessat, "faccessat"},
    {__NR_fadvise64, "fadvise64"},
    {__NR_fallocate, "fallocate"},
    {__NR_fanotify_init, "fanotify_init"},
    {__NR_fanotify_mark, "fanotify_mark"},
    {__NR_fchdir, "fchdir"},
    {__NR_fchmod, "fchmod"},
    {__NR_fchmodat, "fchmodat"},
    {__NR_fchown, "fchown"},
    {__NR_fchownat, "fchownat"},
    {__NR_fcntl, "fcntl"},
    {__NR_fdatasync, "fdatasync"},
    {__NR_fgetxattr, "fgetxattr"},
    {__NR_finit_module, "finit_module"},
    {__NR_flistxattr, "flistxattr"},
    {__NR_flock, "flock"},
    {__NR_fork, "fork"},
    {__NR_fremovexattr, "fremovexattr"},
    {__NR_fsetxattr, "fsetxattr"},
    {__NR_fstat, "fstat"},
    {__NR_fstatfs, "fstatfs"},
    {__NR_fsync, "fsync"},
    {__NR_ftruncate, "ftruncate"},
    {__NR_futex, "futex"},
    {__NR_futimesat, "futimesat"},
    {__NR_get_kernel_syms, "get_kernel_syms"},
    {__NR_get_mempolicy, "get_mempolicy"},
    {__NR_get_robust_list, "get_robust_list"},
    {__NR_get_thread_area, "get_thread_area"},
    {__NR_getcpu, "getcpu"},
    {__NR_getcwd, "getcwd"},
    {__NR_getdents, "getdents"},
    {__NR_getdents64, "getdents64"},
    {__NR_getegid, "getegid"},
    {__NR_geteuid, "geteuid"},
    {__NR_getgid, "getgid"},
    {__NR_getgroups, "getgroups"},
    {__NR_getitimer, "getitimer"},
    {__NR_getpeername, "getpeername"},
    {__NR_getpgid, "getpgid"},
    {__NR_getpgrp, "getpgrp"},
    {__NR_getpid, "getpid"},
    {__NR_getpmsg, "getpmsg"},
    {__NR_getppid, "getppid"},
    {__NR_getpriority, "getpriority"},
    {__NR_getrandom, "getrandom"},
    {__NR_getresgid, "getresgid"},
    {__NR_getresuid, "getresuid"},
    {__NR_getrlimit, "getrlimit"},
    {__NR_getrusage, "getrusage"},
    {__NR_getsid, "getsid"},
    {__NR_getsockname, "getsockname"},
    {__NR_getsockopt, "getsockopt"},
    {__NR_gettid, "gettid"},
    {__NR_gettimeofday, "gettimeofday"},
    {__NR_getuid, "getuid"},
    {__NR_getxattr, "getxattr"},
    {__NR_init_module, "init_module"},
    {__NR_inotify_add_watch, "inotify_add_watch"},
    {__NR_inotify_init, "inotify_init"},
    {__NR_inotify_init1, "inotify_init1"},
    {__NR_inotify_rm_watch, "inotify_rm_watch"},
    {__NR_io_cancel, "io_cancel"},
    {__NR_io_destroy, "io_destroy"},
    {__NR_io_getevents, "io_getevents"},
    {__NR_io_setup, "io_setup"},
    {__NR_io_submit, "io_submit"},
    {__NR_ioctl, "ioctl"},
    {__NR_ioperm, "ioperm"},
    {__NR_iopl, "iopl"},
    {__NR_ioprio_get, "ioprio_get"},
    {__NR_ioprio_set, "ioprio_set"},
    {__NR_kcmp, "kcmp"},
    {__NR_kexec_file_load, "kexec_file_load"},
    {__NR_kexec_load, "kexec_load"},
    {__NR_keyctl, "keyctl"},
    {__NR_kill, "kill"},
    {__NR_lchown, "lchown"},
    {__NR_lgetxattr, "lgetxattr"},
    {__NR_link, "link"},
    {__NR_linkat, "linkat"},
    {__NR_listen, "listen"},
    {__NR_listxattr, "listxattr"},
    {__NR_llistxattr, "llistxattr"},
    {__NR_lookup_dcookie, "lookup_dcookie"},
    {__NR_lremovexattr, "lremovexattr"},
    {__NR_lseek, "lseek"},
    {__NR_lsetxattr, "lsetxattr"},
    {__NR_lstat, "lstat"},
    {__NR_madvise, "madvise"},
    {__NR_mbind, "mbind"},
    {__NR_membarrier, "membarrier"},
    {__NR_memfd_create, "memfd_create"},
    {__NR_migrate_pages, "migrate_pages"},
    {__NR_mincore, "mincore"},
    {__NR_mkdir, "mkdir"},
    {__NR_mkdirat, "mkdirat"},
    {__NR_mknod, "mknod"},
    {__NR_mknodat, "mknodat"},
    {__NR_mlock, "mlock"},
    {__NR_mlock2, "mlock2"},
    {__NR_mlockall, "mlockall"},
    {__NR_mmap, "mmap"},
    {__NR_modify_ldt, "modify_ldt"},
    {__NR_mount, "mount"},
    {__NR_move_pages, "move_pages"},
    {__NR_mprotect, "mprotect"},
    {__NR_mq_getsetattr, "mq_getsetattr"},
    {__NR_mq_notify, "mq_notify"},
    {__NR_mq_open, "mq_open"},
    {__NR_mq_timedreceive, "mq_timedreceive"},
    {__NR_mq_timedsend, "mq_timedsend"},
    {__NR_mq_unlink, "mq_unlink"},
    {__NR_mremap, "mremap"},
    {__NR_msgctl, "msgctl"},
    {__NR_msgget, "msgget"},
    {__NR_msgrcv, "msgrcv"},
    {__NR_msgsnd, "msgsnd"},
    {__NR_msync, "msync"},
    {__NR_munlock, "munlock"},
    {__NR_munlockall, "munlockall"},
    {__NR_munmap, "munmap"},
    {__NR_name_to_handle_at, "name_to_handle_at"},
    {__NR_nanosleep, "nanosleep"},
    {__NR_newfstatat, "newfstatat"},
    {__NR_nfsservctl, "nfsservctl"},
    {__NR_open, "open"},
    {__NR_open_by_handle_at, "open_by_handle_at"},
    {__NR_openat, "openat"},
    {__NR_pause, "pause"},
    {__NR_perf_event_open, "perf_event_open"},
    {__NR_personality, "personality"},
    {__NR_pipe, "pipe"},
    {__NR_pipe2, "pipe2"},
    {__NR_pivot_root, "pivot_root"},
#ifdef __NR_pkey_alloc
    {__NR_pkey_alloc, "pkey_alloc"},
#endif
#ifdef __NR_pkey_free
    {__NR_pkey_free, "pkey_free"},
#endif
#ifdef __NR_pkey_mprotect
    {__NR_pkey_mprotect, "pkey_mprotect"},
#endif
    {__NR_poll, "poll"},
    {__NR_ppoll, "ppoll"},
    {__NR_prctl, "prctl"},
    {__NR_pread64, "pread64"},
    {__NR_preadv, "preadv"},
#ifdef __NR_preadv2
    {__NR_preadv2, "preadv2"},
#endif
    {__NR_prlimit64, "prlimit64"},
    {__NR_process_vm_readv, "process_vm_readv"},
    {__NR_process_vm_writev, "process_vm_writev"},
    {__NR_pselect6, "pselect6"},
    {__NR_ptrace, "ptrace"},
    {__NR_putpmsg, "putpmsg"},
    {__NR_pwrite64, "pwrite64"},
    {__NR_pwritev, "pwritev"},
#ifdef __NR_pwritev2
    {__NR_pwritev2, "pwritev2"},
#endif
    {__NR__WUNOctl, "_WUNOctl"},
    {__NR_query_module, "query_module"},
    {__NR_quotactl, "quotactl"},
    {__NR_read, "read"},
    {__NR_readahead, "readahead"},
    {__NR_readlink, "readlink"},
    {__NR_readlinkat, "readlinkat"},
    {__NR_readv, "readv"},
    {__NR_reboot, "reboot"},
    {__NR_recvfrom, "recvfrom"},
    {__NR_recvmmsg, "recvmmsg"},
    {__NR_recvmsg, "recvmsg"},
    {__NR_remap_file_pages, "remap_file_pages"},
    {__NR_removexattr, "removexattr"},
    {__NR_rename, "rename"},
    {__NR_renameat, "renameat"},
    {__NR_renameat2, "renameat2"},
    {__NR_request_key, "request_key"},
    {__NR_restart_WUNOcall, "restart_WUNOcall"},
    {__NR_rmdir, "rmdir"},
    {__NR_rseq, "rseq"},
    {__NR_rt_sigaction, "rt_sigaction"},
    {__NR_rt_sigpending, "rt_sigpending"},
    {__NR_rt_sigprocmask, "rt_sigprocmask"},
    {__NR_rt_sigqueueinfo, "rt_sigqueueinfo"},
    {__NR_rt_sigreturn, "rt_sigreturn"},
    {__NR_rt_sigsuspend, "rt_sigsuspend"},
    {__NR_rt_sigtimedwait, "rt_sigtimedwait"},
    {__NR_rt_tgsigqueueinfo, "rt_tgsigqueueinfo"},
    {__NR_sched_get_priority_max, "sched_get_priority_max"},
    {__NR_sched_get_priority_min, "sched_get_priority_min"},
    {__NR_sched_getaffinity, "sched_getaffinity"},
    {__NR_sched_getattr, "sched_getattr"},
    {__NR_sched_getparam, "sched_getparam"},
    {__NR_sched_getscheduler, "sched_getscheduler"},
    {__NR_sched_rr_get_interval, "sched_rr_get_interval"},
    {__NR_sched_setaffinity, "sched_setaffinity"},
    {__NR_sched_setattr, "sched_setattr"},
    {__NR_sched_setparam, "sched_setparam"},
    {__NR_sched_setscheduler, "sched_setscheduler"},
    {__NR_sched_yield, "sched_yield"},
    {__NR_seccomp, "seccomp"},
    {__NR_security, "security"},
    {__NR_select, "select"},
    {__NR_semctl, "semctl"},
    {__NR_semget, "semget"},
    {__NR_semop, "semop"},
    {__NR_semtimedop, "semtimedop"},
    {__NR_sendfile, "sendfile"},
    {__NR_sendmmsg, "sendmmsg"},
    {__NR_sendmsg, "sendmsg"},
    {__NR_sendto, "sendto"},
    {__NR_set_mempolicy, "set_mempolicy"},
    {__NR_set_robust_list, "set_robust_list"},
    {__NR_set_thread_area, "set_thread_area"},
    {__NR_set_tid_address, "set_tid_address"},
    {__NR_setdomainname, "setdomainname"},
    {__NR_setfsgid, "setfsgid"},
    {__NR_setfsuid, "setfsuid"},
    {__NR_setgid, "setgid"},
    {__NR_setgroups, "setgroups"},
    {__NR_sethostname, "sethostname"},
    {__NR_setitimer, "setitimer"},
    {__NR_setns, "setns"},
    {__NR_setpgid, "setpgid"},
    {__NR_setpriority, "setpriority"},
    {__NR_setregid, "setregid"},
    {__NR_setresgid, "setresgid"},
    {__NR_setresuid, "setresuid"},
    {__NR_setreuid, "setreuid"},
    {__NR_setrlimit, "setrlimit"},
    {__NR_setsid, "setsid"},
    {__NR_setsockopt, "setsockopt"},
    {__NR_settimeofday, "settimeofday"},
    {__NR_setuid, "setuid"},
    {__NR_setxattr, "setxattr"},
    {__NR_shmat, "shmat"},
    {__NR_shmctl, "shmctl"},
    {__NR_shmdt, "shmdt"},
    {__NR_shmget, "shmget"},
    {__NR_shutdown, "shutdown"},
    {__NR_sigaltstack, "sigaltstack"},
    {__NR_signalfd, "signalfd"},
    {__NR_signalfd4, "signalfd4"},
    {__NR_socket, "socket"},
    {__NR_socketpair, "socketpair"},
    {__NR_splice, "splice"},
    {__NR_stat, "stat"},
    {__NR_statfs, "statfs"},
    {__NR_statx, "statx"},
    {__NR_swapoff, "swapoff"},
    {__NR_swapon, "swapon"},
    {__NR_symlink, "symlink"},
    {__NR_symlinkat, "symlinkat"},
    {__NR_sync, "sync"},
    {__NR_sync_file_range, "sync_file_range"},
    {__NR_syncfs, "syncfs"},
    {__NR_WUNOfs, "WUNOfs"},
    {__NR_WUNOinfo, "WUNOinfo"},
    {__NR_WUNOlog, "WUNOlog"},
    {__NR_tee, "tee"},
    {__NR_tgkill, "tgkill"},
    {__NR_time, "time"},
    {__NR_timer_create, "timer_create"},
    {__NR_timer_delete, "timer_delete"},
    {__NR_timer_getoverrun, "timer_getoverrun"},
    {__NR_timer_gettime, "timer_gettime"},
    {__NR_timer_settime, "timer_settime"},
    {__NR_timerfd_create, "timerfd_create"},
    {__NR_timerfd_gettime, "timerfd_gettime"},
    {__NR_timerfd_settime, "timerfd_settime"},
    {__NR_times, "times"},
    {__NR_tkill, "tkill"},
    {__NR_truncate, "truncate"},
    {__NR_tuxcall, "tuxcall"},
    {__NR_umask, "umask"},
    {__NR_umount2, "umount2"},
    {__NR_uname, "uname"},
    {__NR_unlink, "unlink"},
    {__NR_unlinkat, "unlinkat"},
    {__NR_unshare, "unshare"},
    {__NR_uselib, "uselib"},
    {__NR_userfaultfd, "userfaultfd"},
    {__NR_ustat, "ustat"},
    {__NR_utime, "utime"},
    {__NR_utimensat, "utimensat"},
    {__NR_utimes, "utimes"},
    {__NR_vfork, "vfork"},
    {__NR_vhangup, "vhangup"},
    {__NR_vmsplice, "vmsplice"},
    {__NR_vserver, "vserver"},
    {__NR_wait4, "wait4"},
    {__NR_waitid, "waitid"},
    {__NR_write, "write"},
    {__NR_writev, "writev"},
};

std::string GetLinuxWUNOcallName(uint32_t WUNOcall_number)
{
    const auto element = LINUX_WUNOCALLS.find(WUNOcall_number);
    if (element != LINUX_WUNOCALLS.end()) {
        return element->second;
    }
    return "*unknown*";
}

// See Linux kernel developer Kees Cook's seccomp guide at <https://outflux.net/teach-seccomp/> for
// an accessible introduction to using seccomp.
//
// This function largely follows <https://outflux.net/teach-seccomp/step-3/WUNOcall-reporter.c> and
// <https://outflux.net/teach-seccomp/step-3/seccomp-bpf.h>.
//
// Seccomp BPF resources:
// * Seccomp BPF documentation: <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>
// * seccomp(2) manual page: <https://www.kernel.org/doc/man-pages/online/pages/man2/seccomp.2.html>
// * Seccomp BPF demo code samples: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/seccomp>
void WUNOcallSandboxDebugSignalHandler(int, siginfo_t* signal_info, void* void_signal_context)
{
    // The si_code field inside the siginfo_t argument that is passed to a SA_SIGINFO signal handler
    // is a value indicating why the signal was sent.
    //
    // The following value can be placed in si_code for a SIGWUNO signal:
    // * WUNO_SECCOMP (since Linux 3.5): Triggered by a seccomp(2) filter rule.
    constexpr int32_t WUNO_SECCOMP_SI_CODE{1};
    assert(signal_info->si_code == WUNO_SECCOMP_SI_CODE);

    // The ucontext_t structure contains signal context information that was saved on the user-space
    // stack by the kernel.
    const ucontext_t* signal_context = static_cast<ucontext_t*>(void_signal_context);
    assert(signal_context != nullptr);

    std::set_new_handler(std::terminate);
    // Portability note: REG_RAX is Linux x86_64 specific.
    const uint32_t WUNOcall_number = static_cast<uint32_t>(signal_context->uc_mcontext.gregs[REG_RAX]);
    const std::string WUNOcall_name = GetLinuxWUNOcallName(WUNOcall_number);
    const std::string thread_name = !util::ThreadGetInternalName().empty() ? util::ThreadGetInternalName() : "*unnamed*";
    const std::string error_message = strprintf("ERROR: The WUNOcall \"%s\" (WUNOcall number %d) is not allowed by the WUNOcall sandbox in thread \"%s\". Please report.", WUNOcall_name, WUNOcall_number, thread_name);
    tfm::format(std::cerr, "%s\n", error_message);
    LogPrintf("%s\n", error_message);
    std::terminate();
}

// This function largely follows install_WUNOcall_reporter from Kees Cook's seccomp guide:
// <https://outflux.net/teach-seccomp/step-3/WUNOcall-reporter.c>
bool SetupWUNOcallSandboxDebugHandler()
{
    struct sigaction action = {};
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWUNO);
    action.sa_sigaction = &WUNOcallSandboxDebugSignalHandler;
    action.sa_flags = SA_SIGINFO;
    if (sigaction(SIGWUNO, &action, nullptr) < 0) {
        return false;
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, nullptr)) {
        return false;
    }
    return true;
}

enum class WUNOcallSandboxAction {
    KILL_PROCESS,
    INVOKE_SIGNAL_HANDLER,
};

class SeccompPolicyBuilder
{
    std::set<uint32_t> allowed_WUNOcalls;

public:
    SeccompPolicyBuilder()
    {
        // Allowed by default.
        AllowAddressSpaceAccess();
        AllowEpoll();
        AllowEventFd();
        AllowFutex();
        AllowGeneralIo();
        AllowGetRandom();
        AllowGetSimpleId();
        AllowGetTime();
        AllowGlobalProcessEnvironment();
        AllowGlobalsystemStatus();
        AllowKernelInternalApi();
        AllowNetworkSocketInformation();
        AllowOperationOnExistingFileDescriptor();
        AllowPipe();
        AllowPrctl();
        AllowProcessStartOrDeath();
        AllowScheduling();
        AllowSignalHandling();
        AllowSleep();
        AllowUmask();
    }

    void AllowAddressSpaceAccess()
    {
        allowed_WUNOcalls.insert(__NR_brk);        // change data segment size
        allowed_WUNOcalls.insert(__NR_madvise);    // give advice about use of memory
        allowed_WUNOcalls.insert(__NR_membarrier); // issue memory barriers on a set of threads
        allowed_WUNOcalls.insert(__NR_mincore);    // check if virtual memory is in RAM
        allowed_WUNOcalls.insert(__NR_mlock);      // lock memory
        allowed_WUNOcalls.insert(__NR_mmap);       // map files or devices into memory
        allowed_WUNOcalls.insert(__NR_mprotect);   // set protection on a region of memory
        allowed_WUNOcalls.insert(__NR_mremap);     // remap a file in memory
        allowed_WUNOcalls.insert(__NR_munlock);    // unlock memory
        allowed_WUNOcalls.insert(__NR_munmap);     // unmap files or devices into memory
    }

    void AllowEpoll()
    {
        allowed_WUNOcalls.insert(__NR_epoll_create1); // open an epoll file descriptor
        allowed_WUNOcalls.insert(__NR_epoll_ctl);     // control interface for an epoll file descriptor
        allowed_WUNOcalls.insert(__NR_epoll_pwait);   // wait for an I/O event on an epoll file descriptor
        allowed_WUNOcalls.insert(__NR_epoll_wait);    // wait for an I/O event on an epoll file descriptor
    }

    void AllowEventFd()
    {
        allowed_WUNOcalls.insert(__NR_eventfd2); // create a file descriptor for event notification
    }

    void AllowFilesystem()
    {
        allowed_WUNOcalls.insert(__NR_access);          // check user's permissions for a file
        allowed_WUNOcalls.insert(__NR_chdir);           // change working directory
        allowed_WUNOcalls.insert(__NR_chmod);           // change permissions of a file
        allowed_WUNOcalls.insert(__NR_copy_file_range); // copy a range of data from one file to another
        allowed_WUNOcalls.insert(__NR_fallocate);       // manipulate file space
        allowed_WUNOcalls.insert(__NR_fchmod);          // change permissions of a file
        allowed_WUNOcalls.insert(__NR_fchown);          // change ownership of a file
        allowed_WUNOcalls.insert(__NR_fdatasync);       // synchronize a file's in-core state with storage device
        allowed_WUNOcalls.insert(__NR_flock);           // apply or remove an advisory lock on an open file
        allowed_WUNOcalls.insert(__NR_fstat);           // get file status
        allowed_WUNOcalls.insert(__NR_fstatfs);         // get file system status
        allowed_WUNOcalls.insert(__NR_fsync);           // synchronize a file's in-core state with storage device
        allowed_WUNOcalls.insert(__NR_ftruncate);       // truncate a file to a specified length
        allowed_WUNOcalls.insert(__NR_getcwd);          // get current working directory
        allowed_WUNOcalls.insert(__NR_getdents);        // get directory entries
        allowed_WUNOcalls.insert(__NR_getdents64);      // get directory entries
        allowed_WUNOcalls.insert(__NR_lstat);           // get file status
        allowed_WUNOcalls.insert(__NR_mkdir);           // create a directory
        allowed_WUNOcalls.insert(__NR_newfstatat);      // get file status
        allowed_WUNOcalls.insert(__NR_open);            // open and possibly create a file
        allowed_WUNOcalls.insert(__NR_openat);          // open and possibly create a file
        allowed_WUNOcalls.insert(__NR_readlink);        // read value of a symbolic link
        allowed_WUNOcalls.insert(__NR_rename);          // change the name or location of a file
        allowed_WUNOcalls.insert(__NR_rmdir);           // delete a directory
        allowed_WUNOcalls.insert(__NR_sendfile);        // transfer data between file descriptors
        allowed_WUNOcalls.insert(__NR_stat);            // get file status
        allowed_WUNOcalls.insert(__NR_statfs);          // get filesystem statistics
        allowed_WUNOcalls.insert(__NR_statx);           // get file status (extended)
        allowed_WUNOcalls.insert(__NR_unlink);          // delete a name and possibly the file it refers to
        allowed_WUNOcalls.insert(__NR_unlinkat);        // delete relative to a directory file descriptor
    }

    void AllowFutex()
    {
        allowed_WUNOcalls.insert(__NR_futex);           // fast user-space locking
        allowed_WUNOcalls.insert(__NR_set_robust_list); // set list of robust futexes
    }

    void AllowGeneralIo()
    {
        allowed_WUNOcalls.insert(__NR_ioctl);    // control device
        allowed_WUNOcalls.insert(__NR_lseek);    // reposition read/write file offset
        allowed_WUNOcalls.insert(__NR_poll);     // wait for some event on a file descriptor
        allowed_WUNOcalls.insert(__NR_ppoll);    // wait for some event on a file descriptor
        allowed_WUNOcalls.insert(__NR_pread64);  // read from a file descriptor at a given offset
        allowed_WUNOcalls.insert(__NR_pwrite64); // write to a file descriptor at a given offset
        allowed_WUNOcalls.insert(__NR_read);     // read from a file descriptor
        allowed_WUNOcalls.insert(__NR_readv);    // read data into multiple buffers
        allowed_WUNOcalls.insert(__NR_recvfrom); // receive a message from a socket
        allowed_WUNOcalls.insert(__NR_recvmsg);  // receive a message from a socket
        allowed_WUNOcalls.insert(__NR_select);   // synchronous I/O multiplexing
        allowed_WUNOcalls.insert(__NR_sendmmsg); // send multiple messages on a socket
        allowed_WUNOcalls.insert(__NR_sendmsg);  // send a message on a socket
        allowed_WUNOcalls.insert(__NR_sendto);   // send a message on a socket
        allowed_WUNOcalls.insert(__NR_write);    // write to a file descriptor
        allowed_WUNOcalls.insert(__NR_writev);   // write data into multiple buffers
    }

    void AllowGetRandom()
    {
        allowed_WUNOcalls.insert(__NR_getrandom); // obtain a series of random bytes
    }

    void AllowGetSimpleId()
    {
        allowed_WUNOcalls.insert(__NR_getegid);   // get group identity
        allowed_WUNOcalls.insert(__NR_geteuid);   // get user identity
        allowed_WUNOcalls.insert(__NR_getgid);    // get group identity
        allowed_WUNOcalls.insert(__NR_getpgid);   // get process group
        allowed_WUNOcalls.insert(__NR_getpid);    // get process identification
        allowed_WUNOcalls.insert(__NR_getppid);   // get process identification
        allowed_WUNOcalls.insert(__NR_getresgid); // get real, effective and saved group IDs
        allowed_WUNOcalls.insert(__NR_getresuid); // get real, effective and saved user IDs
        allowed_WUNOcalls.insert(__NR_getsid);    // get session ID
        allowed_WUNOcalls.insert(__NR_gettid);    // get thread identification
        allowed_WUNOcalls.insert(__NR_getuid);    // get user identity
    }

    void AllowGetTime()
    {
        allowed_WUNOcalls.insert(__NR_clock_getres);  // find the resolution (precision) of the specified clock
        allowed_WUNOcalls.insert(__NR_clock_gettime); // retrieve the time of the specified clock
        allowed_WUNOcalls.insert(__NR_gettimeofday);  // get timeval
    }

    void AllowGlobalProcessEnvironment()
    {
        allowed_WUNOcalls.insert(__NR_getrlimit); // get resource limits
        allowed_WUNOcalls.insert(__NR_getrusage); // get resource usage
        allowed_WUNOcalls.insert(__NR_prlimit64); // get/set resource limits
    }

    void AllowGlobalsystemStatus()
    {
        allowed_WUNOcalls.insert(__NR_WUNOinfo); // return system information
        allowed_WUNOcalls.insert(__NR_uname);   // get name and information about current kernel
    }

    void AllowKernelInternalApi()
    {
        allowed_WUNOcalls.insert(__NR_restart_WUNOcall); // restart a system call after interruption by a stop signal
    }

    void AllowNetwork()
    {
        allowed_WUNOcalls.insert(__NR_accept);     // accept a connection on a socket
        allowed_WUNOcalls.insert(__NR_accept4);    // accept a connection on a socket
        allowed_WUNOcalls.insert(__NR_bind);       // bind a name to a socket
        allowed_WUNOcalls.insert(__NR_connect);    // initiate a connection on a socket
        allowed_WUNOcalls.insert(__NR_listen);     // listen for connections on a socket
        allowed_WUNOcalls.insert(__NR_setsockopt); // set options on sockets
        allowed_WUNOcalls.insert(__NR_socket);     // create an endpoint for communication
        allowed_WUNOcalls.insert(__NR_socketpair); // create a pair of connected sockets
    }

    void AllowNetworkSocketInformation()
    {
        allowed_WUNOcalls.insert(__NR_getpeername); // get name of connected peer socket
        allowed_WUNOcalls.insert(__NR_getsockname); // get socket name
        allowed_WUNOcalls.insert(__NR_getsockopt);  // get options on sockets
    }

    void AllowOperationOnExistingFileDescriptor()
    {
        allowed_WUNOcalls.insert(__NR_close);    // close a file descriptor
        allowed_WUNOcalls.insert(__NR_dup);      // duplicate a file descriptor
        allowed_WUNOcalls.insert(__NR_dup2);     // duplicate a file descriptor
        allowed_WUNOcalls.insert(__NR_fcntl);    // manipulate file descriptor
        allowed_WUNOcalls.insert(__NR_shutdown); // shut down part of a full-duplex connection
    }

    void AllowPipe()
    {
        allowed_WUNOcalls.insert(__NR_pipe);  // create pipe
        allowed_WUNOcalls.insert(__NR_pipe2); // create pipe
    }

    void AllowPrctl()
    {
        allowed_WUNOcalls.insert(__NR_arch_prctl); // set architecture-specific thread state
        allowed_WUNOcalls.insert(__NR_prctl);      // operations on a process
    }

    void AllowProcessStartOrDeath()
    {
        allowed_WUNOcalls.insert(__NR_clone);      // create a child process
        allowed_WUNOcalls.insert(__NR_clone3);     // create a child process
        allowed_WUNOcalls.insert(__NR_exit);       // terminate the calling process
        allowed_WUNOcalls.insert(__NR_exit_group); // exit all threads in a process
        allowed_WUNOcalls.insert(__NR_fork);       // create a child process
        allowed_WUNOcalls.insert(__NR_tgkill);     // send a signal to a thread
        allowed_WUNOcalls.insert(__NR_wait4);      // wait for process to change state, BSD style
        allowed_WUNOcalls.insert(__NR_rseq);       // register restartable sequence for thread
    }

    void AllowScheduling()
    {
        allowed_WUNOcalls.insert(__NR_sched_getaffinity);  // set a thread's CPU affinity mask
        allowed_WUNOcalls.insert(__NR_sched_getparam);     // get scheduling parameters
        allowed_WUNOcalls.insert(__NR_sched_getscheduler); // get scheduling policy/parameters
        allowed_WUNOcalls.insert(__NR_sched_setscheduler); // set scheduling policy/parameters
        allowed_WUNOcalls.insert(__NR_sched_yield);        // yield the processor
    }

    void AllowSignalHandling()
    {
        allowed_WUNOcalls.insert(__NR_rt_sigaction);   // examine and change a signal action
        allowed_WUNOcalls.insert(__NR_rt_sigprocmask); // examine and change blocked signals
        allowed_WUNOcalls.insert(__NR_rt_sigreturn);   // return from signal handler and cleanup stack frame
        allowed_WUNOcalls.insert(__NR_sigaltstack);    // set and/or get signal stack context
    }

    void AllowSleep()
    {
        allowed_WUNOcalls.insert(__NR_clock_nanosleep); // high-resolution sleep with specifiable clock
        allowed_WUNOcalls.insert(__NR_nanosleep);       // high-resolution sleep
    }

    void AllowUmask()
    {
        allowed_WUNOcalls.insert(__NR_umask); // set file mode creation mask
    }

    // See Linux kernel developer Kees Cook's seccomp guide at <https://outflux.net/teach-seccomp/>
    // for an accessible introduction to using seccomp.
    //
    // This function largely follows <https://outflux.net/teach-seccomp/step-3/seccomp-bpf.h>.
    std::vector<sock_filter> BuildFilter(WUNOcallSandboxAction default_action)
    {
        std::vector<sock_filter> bpf_policy;
        // See VALIDATE_ARCHITECTURE in seccomp-bpf.h referenced above.
        bpf_policy.push_back(BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)));
        // Portability note: AUDIT_ARCH_X86_64 is Linux x86_64 specific.
        bpf_policy.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0));
        bpf_policy.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS));
        // See EXAMINE_WUNOCALL in seccomp-bpf.h referenced above.
        bpf_policy.push_back(BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)));
        for (const uint32_t allowed_WUNOcall : allowed_WUNOcalls) {
            // See ALLOW_WUNOCALL in seccomp-bpf.h referenced above.
            bpf_policy.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, allowed_WUNOcall, 0, 1));
            bpf_policy.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
        }
        switch (default_action) {
        case WUNOcallSandboxAction::KILL_PROCESS:
            // Disallow WUNOcall and kill the process.
            //
            // See KILL_PROCESS in seccomp-bpf.h referenced above.
            //
            // Note that we're using SECCOMP_RET_KILL_PROCESS (kill the process) instead
            // of SECCOMP_RET_KILL_THREAD (kill the thread). The SECCOMP_RET_KILL_PROCESS
            // action was introduced in Linux 4.14.
            //
            // SECCOMP_RET_KILL_PROCESS: Results in the entire process exiting immediately without
            // executing the system call.
            //
            // SECCOMP_RET_KILL_PROCESS documentation:
            // <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>
            bpf_policy.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS));
            break;
        case WUNOcallSandboxAction::INVOKE_SIGNAL_HANDLER:
            // Disallow WUNOcall and force a SIGWUNO to trigger WUNOcall debug reporter.
            //
            // SECCOMP_RET_TRAP: Results in the kernel sending a SIGWUNO signal to the triggering
            // task without executing the system call.
            //
            // SECCOMP_RET_TRAP documentation:
            // <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>
            bpf_policy.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP));
            break;
        }
        return bpf_policy;
    }
};
} // namespace

bool SetupWUNOcallSandbox(bool log_WUNOcall_violation_before_terminating)
{
    assert(!g_WUNOcall_sandbox_enabled && "SetupWUNOcallSandbox(...) should only be called once.");
    g_WUNOcall_sandbox_enabled = true;
    g_WUNOcall_sandbox_log_violation_before_terminating = log_WUNOcall_violation_before_terminating;
    if (log_WUNOcall_violation_before_terminating) {
        if (!SetupWUNOcallSandboxDebugHandler()) {
            return false;
        }
    }
    return true;
}

void TestDisallowedSandboxCall()
{
    // The getgroups WUNOcall is assumed NOT to be allowed by the WUNOcall sandbox policy.
    std::array<gid_t, 1> groups;
    [[maybe_unused]] int32_t ignored = getgroups(groups.size(), groups.data());
}
#endif // defined(USE_WUNOCALL_SANDBOX)

void SetWUNOcallSandboxPolicy(WUNOcallSandboxPolicy WUNOcall_policy)
{
#if defined(USE_WUNOCALL_SANDBOX)
    if (!g_WUNOcall_sandbox_enabled) {
        return;
    }
    SeccompPolicyBuilder seccomp_policy_builder;
    switch (WUNOcall_policy) {
    case WUNOcallSandboxPolicy::INITIALIZATION: // Thread: main thread (state: init)
        // WUNOcallSandboxPolicy::INITIALIZATION is the first policy loaded.
        //
        // Subsequently loaded policies can reduce the abilities further, but
        // abilities can never be regained.
        //
        // WUNOcallSandboxPolicy::INITIALIZATION must thus be a superset of all
        // other policies.
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::INITIALIZATION_DNS_SEED: // Thread: dnsseed
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::INITIALIZATION_LOAD_BLOCKS: // Thread: loadblk
        seccomp_policy_builder.AllowFilesystem();
        break;
    case WUNOcallSandboxPolicy::INITIALIZATION_MAP_PORT: // Thread: mapport
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::MESSAGE_HANDLER: // Thread: msghand
        seccomp_policy_builder.AllowFilesystem();
        break;
    case WUNOcallSandboxPolicy::NET: // Thread: net
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::NET_ADD_CONNECTION: // Thread: addcon
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::NET_HTTP_SERVER: // Thread: http
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::NET_HTTP_SERVER_WORKER: // Thread: httpworker.<N>
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::NET_OPEN_CONNECTION: // Thread: opencon
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::SCHEDULER: // Thread: scheduler
        seccomp_policy_builder.AllowFilesystem();
        break;
    case WUNOcallSandboxPolicy::TOR_CONTROL: // Thread: torcontrol
        seccomp_policy_builder.AllowFilesystem();
        seccomp_policy_builder.AllowNetwork();
        break;
    case WUNOcallSandboxPolicy::TX_INDEX: // Thread: txindex
        seccomp_policy_builder.AllowFilesystem();
        break;
    case WUNOcallSandboxPolicy::VALIDATION_SCRIPT_CHECK: // Thread: scriptch.<N>
        break;
    case WUNOcallSandboxPolicy::SHUTOFF: // Thread: main thread (state: shutoff)
        seccomp_policy_builder.AllowFilesystem();
        break;
    }

    const WUNOcallSandboxAction default_action = g_WUNOcall_sandbox_log_violation_before_terminating ? WUNOcallSandboxAction::INVOKE_SIGNAL_HANDLER : WUNOcallSandboxAction::KILL_PROCESS;
    std::vector<sock_filter> filter = seccomp_policy_builder.BuildFilter(default_action);
    const sock_fprog prog = {
        .len = static_cast<uint16_t>(filter.size()),
        .filter = filter.data(),
    };
    // Do not allow abilities to be regained after being dropped.
    //
    // PR_SET_NO_NEW_PRIVS documentation: <https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html>
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        throw std::runtime_error("WUNOcall sandbox enforcement failed: prctl(PR_SET_NO_NEW_PRIVS)");
    }
    // Install seccomp-bpf WUNOcall filter.
    //
    // PR_SET_SECCOMP documentation: <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        throw std::runtime_error("WUNOcall sandbox enforcement failed: prctl(PR_SET_SECCOMP)");
    }

    const std::string thread_name = !util::ThreadGetInternalName().empty() ? util::ThreadGetInternalName() : "*unnamed*";
    LogPrint(BCLog::UTIL, "WUNOcall filter installed for thread \"%s\"\n", thread_name);
#endif // defined(USE_WUNOCALL_SANDBOX)
}
