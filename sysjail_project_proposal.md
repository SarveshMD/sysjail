# Policy-Driven Process Confinement and Sandboxing via Kernel-Level Syscall Filtering

## 1. Project Overview and Scope

**SysJail** is a lightweight, policy-driven userspace sandbox launcher
written in C for Linux, including Ubuntu/Debian environments running
under WSL 2. It launches a target program as a child process and applies
Linux **seccomp** filtering through **libseccomp** before executing the
target.

Seccomp filters are evaluated by the Linux kernel when a process makes a
system call. This provides a stronger enforcement boundary than
userspace interposition techniques such as `LD_PRELOAD`, which can be
bypassed by static binaries or direct system-call instructions.

**Scope note:** seccomp filters restrict system calls; they are not a
complete sandbox by themselves. They do not provide general filesystem
isolation, prevent access through already-open file descriptors, or
replace namespaces, capabilities, or other OS isolation mechanisms. This
project demonstrates syscall-level confinement, not a complete
hostile-code containment system.

------------------------------------------------------------------------

## 2. Core Operating-System Concepts

-   **System calls:** The interface through which a userspace process
    requests services from the kernel.
-   **Seccomp-BPF:** Linux evaluates a filter over syscall metadata,
    such as the syscall number and selected argument values, before
    allowing the call to proceed.
-   **Privilege hardening:** The launcher sets `PR_SET_NO_NEW_PRIVS`
    before loading the filter. This prevents the process and its
    descendants from gaining additional privileges through `execve()`
    mechanisms such as set-user-ID programs.
-   **Process inheritance:** Seccomp filters are inherited by child
    processes created with `fork()` or `clone()`, and persist across
    `execve()`. A filter does not need to be reinstalled after a
    successful `execve()`.
-   **Violation handling:** Policies can return an error such as
    `EPERM`, terminate a process, or raise `SIGSYS` for a trapped
    syscall. The selected action determines what the parent can observe.

### Important implementation distinction

A `SIGSYS` handler can inspect `siginfo_t` (including `si_syscall` on
supported Linux architectures) when using `SECCOMP_RET_TRAP`. If a
process is killed with `SECCOMP_RET_KILL_PROCESS`, the parent can detect
the termination status with `waitpid()`, but **cannot reliably recover
the violating syscall number from that wait status alone**. If reporting
syscall IDs is required, use a trap-based design or another explicit
reporting mechanism.

------------------------------------------------------------------------

## 3. Architecture and Execution Pipeline

``` text
[ CLI Invocation ]
        |
        v
[ Parse command line and select policy ]
        |
        v
[ Fork child process ]
        |
        +--------------------------+
        |                          |
        v                          v
[ Parent process ]           [ Child process ]
        |                          |
        |                    Set PR_SET_NO_NEW_PRIVS
        |                          |
        |                    Create libseccomp context
        |                          |
        |                    Add policy rules
        |                          |
        |                    Load filter with seccomp_load()
        |                          |
        |                    execvp(target, args)
        |                          |
        v                          v
[ waitpid() ]                [ Target runs under filter ]
        |
        v
[ Report exit code or terminating signal ]
```

The launcher should install the filter in the child immediately before
executing the target. Use `execvp()` if the command should be resolved
through `PATH`; use `execve()` when an explicit executable path and
environment are supplied.

------------------------------------------------------------------------

## 4. Proposed Policy Profiles

These profiles are **demonstration policies**, not security-complete
profiles. Test each profile with the actual target program because
dynamically linked programs may require additional syscalls for startup,
threading, locale handling, and runtime support.

### 4.1 `compute-only` --- Restricted Worker

**Intent:** Allow a small set of operations needed by a simple
compute-oriented program.

Potentially allowed syscalls include:

-   Basic output: `write` (ideally restricted to standard output/error
    file descriptors where practical)
-   Process termination: `exit`, `exit_group`
-   Memory management: `brk`, `mmap`, `munmap`, `mprotect`
-   Runtime support where needed: selected signal and thread-related
    syscalls

**Blocked examples:**

-   Network-related calls such as `socket`, `connect`, `bind`, and
    `listen`
-   Process creation calls such as `fork`, `vfork`, and `clone`
-   File-opening calls such as `open`, `openat`, and `creat`

A strict allowlist can cause ordinary programs to fail because the C
runtime and loader may need syscalls not listed above. Start with a
minimal test binary and add only the calls required by the intended
workload.

### 4.2 `no-network` --- Network-Restricted Process

**Intent:** Deny common socket operations while preserving general file
and process operations.

Commonly blocked syscalls include:

-   `socket`, `socketpair`
-   `connect`, `bind`, `listen`, `accept`, `accept4`
-   `sendto`, `sendmsg`, `recvfrom`, `recvmsg`

This list is illustrative, not exhaustive. Network access can also occur
through existing socket file descriptors or file descriptors passed to
the process. A seccomp policy is therefore not equivalent to full
network isolation. For stronger isolation, combine it with suitable
network namespaces and other controls.

### 4.3 `read-only-fs` --- Limited Filesystem Mutation

**Intent:** Demonstrate blocking selected filesystem-mutating syscalls.

Potentially blocked calls include:

-   `unlink`, `unlinkat`, `rmdir`
-   `rename`, `renameat`, `renameat2`
-   `mkdir`, `mkdirat`
-   `chmod`, `fchmod`, `fchmodat`
-   `chown`, `fchown`, `fchownat`
-   `truncate`, `ftruncate`

**Critical limitation:** seccomp cannot generally determine whether a
`write()` file descriptor refers to a regular file, a terminal, a pipe,
or another object. Nor does blocking a list of mutation syscalls make
the entire filesystem read-only. A filter can inspect arguments such as
`openat()` flags, but that alone is not a complete or reliable
filesystem sandbox.

For actual read-only filesystem confinement, use a read-only mount
namespace or another filesystem isolation mechanism. In this project,
name the profile something like `deny-common-mutations` unless
filesystem isolation is implemented separately.

------------------------------------------------------------------------

## 5. Minimal Working Prototype

### 5.1 Command-line interface

The executable is named `sysjail`.

``` bash
./sysjail --policy <compute-only|no-network|read-only-fs> -- <program> [args...]

# Examples
./sysjail --policy compute-only -- /bin/echo "Hello Sandboxed World"
./sysjail --policy no-network -- /usr/bin/curl -I https://example.com
./sysjail --policy read-only-fs -- /bin/rm -rf /tmp/testfile
```

The final example is only a useful demonstration if the chosen policy
actually blocks the relevant removal syscalls. The profile name should
not imply complete filesystem read-only enforcement unless that
isolation is implemented.

### 5.2 Expected behavior

-   **Allowed operation:** The target runs and returns its normal exit
    status.
-   **Denied syscall with `SCMP_ACT_ERRNO(EPERM)`:** The syscall fails
    with `EPERM`; the program may print a permission error or handle the
    failure silently.
-   **Trapped syscall with `SCMP_ACT_TRAP`:** The kernel delivers
    `SIGSYS`. A suitable handler can log the syscall number and relevant
    context, subject to architecture and async-signal-safety
    constraints.
-   **Killed process with `SCMP_ACT_KILL_PROCESS`:** The kernel
    terminates the process. The parent can report that the process was
    killed by a signal, but `waitpid()` alone does not reveal the
    syscall number.

Do not promise that `curl` will always produce a particular error
message: the message depends on the denied syscall, the library, and the
program's own error handling.

------------------------------------------------------------------------

## 6. Technical Stack and Dependencies

-   **Language:** C (C99 or C11)
-   **Platform:** Linux; Ubuntu/Debian under WSL 2 is a suitable
    development environment
-   **Library:** `libseccomp`
-   **Headers:** `seccomp.h`, `sys/prctl.h`, `sys/wait.h`, `unistd.h`,
    `errno.h`, `signal.h`
-   **Build tools:** GCC or Clang, plus `make`

On Ubuntu/Debian, install the development package:

``` bash
sudo apt update
sudo apt install build-essential libseccomp-dev
```

A minimal build command is:

``` bash
gcc -std=c11 -Wall -Wextra -Wpedantic -O2 -o sysjail sysjail.c -lseccomp
```

A `Makefile` can wrap this command for repeatable builds.

------------------------------------------------------------------------

## 7. Implementation Roadmap

### Phase 1 --- Proof of Concept

1.  Create a small C program using libseccomp.
2.  Set `PR_SET_NO_NEW_PRIVS`.
3.  Create a filter that returns `EPERM` for a selected syscall, such as
    `mkdir`.
4.  Load the filter with `seccomp_load()`.
5.  Verify that `mkdir()` fails with `errno == EPERM`, while permitted
    operations continue to work.

### Phase 2 --- Execution Launcher

1.  Parse the command line and require `--` before the target command.
2.  Fork a child process.
3.  In the child, set `PR_SET_NO_NEW_PRIVS`, construct and load the
    selected filter, then execute the target.
4.  In the parent, call `waitpid()` and report the child's exit code or
    terminating signal.
5.  Handle setup and `exec` failures clearly, ensuring the parent can
    distinguish them from a target program's exit status.

### Phase 3 --- Policy Profiles and Auditing

1.  Implement named policy profiles.
2.  Add clear error handling for invalid policies and failed libseccomp
    calls.
3.  Support `ERRNO`, `TRAP`, or `KILL_PROCESS` actions according to the
    demonstration goal.
4.  If logging syscall IDs, use a design that can actually obtain them,
    such as `SECCOMP_RET_TRAP` with a carefully implemented `SIGSYS`
    handler.
5.  Document each profile's limitations and test it against a known set
    of commands.

### Phase 4 --- Testing and Demonstration

-   Confirm a permitted command runs successfully.
-   Confirm a blocked syscall fails or terminates the target as
    configured.
-   Test an ordinary dynamically linked program to identify required
    runtime syscalls.
-   Test on the intended Linux/WSL 2 environment and document kernel or
    architecture assumptions.

------------------------------------------------------------------------

## 8. Success Criteria

The prototype is successful when it:

1.  Builds cleanly with the documented compiler command.
2.  Launches a target command with the selected seccomp filter active.
3.  Demonstrates at least one allowed syscall and one denied syscall.
4.  Reports the target's exit status or terminating signal correctly.
5.  Explains the difference between syscall filtering and full
    sandboxing, especially for filesystem and network isolation.

**Project boundary:** SysJail is a teaching prototype for
kernel-enforced syscall filtering. It should not be presented as a
complete security boundary for running actively malicious code without
additional isolation controls.
