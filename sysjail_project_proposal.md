# SysJail Project Brief

## Purpose

SysJail is a small C launcher for Ubuntu under WSL 2. It starts a target
program as a child, applies a libseccomp policy, and then replaces the child
with the target program.

The project demonstrates how Linux can reject selected system calls before
they reach the kernel service that would perform them. The launcher uses
`PR_SET_NO_NEW_PRIVS` before loading the filter and reports the target's exit
status or terminating signal.

## Policies

The implementation provides three teaching policies:

- `compute-only` blocks common directory mutation, networking, and process
  creation calls.
- `no-network` blocks common socket and network message calls.
- `read-only-fs` blocks common filesystem mutation calls such as `mkdir`,
  `unlink`, `rename`, and `truncate`.

These are small deny lists intended for demonstrations. They are not complete
allowlists and should be tested with the actual target program.

## Boundary

Seccomp filters system calls, not all behavior. This project does not provide
complete filesystem isolation, network isolation, resource limits, namespace
isolation, or protection from actively hostile code. Existing file descriptors
and other kernel interfaces can still matter. A production sandbox would need
additional controls such as namespaces, mount restrictions, capabilities, and
resource limits.

## Platform and dependency

Build and run on Linux, especially Ubuntu under WSL 2, with GCC, Make, and
`libseccomp-dev`. The build and demonstration commands are documented in
`README.md`; the implementation roadmap and validation checklist are in
`PLAN.md`.
