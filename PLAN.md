# SysJail Implementation Plan

## Goal

Build a small Linux/WSL 2 command launcher that applies a libseccomp policy in
its child process before `execvp()`. The project demonstrates syscall filtering;
it is not a complete filesystem, network, or hostile-code sandbox.

The launcher owns messages prefixed with `[sysjail]`. It prints the selected
policy, the complete target command, and the target's final status. The executed
program owns its own output, including errors caused by a denied syscall. The
sample targets prefix their messages with `[target]` so this distinction is
visible; external programs retain their normal output.

## Work Items

1. Replace the proof-of-concept launcher with a command-line interface:
   - `sysjail --policy <compute-only|no-network|read-only-fs> -- <program> [args...]`
   - validate the policy and require the `--` separator
   - apply the selected filter in the child process
   - report target exit codes and terminating signals
   - report launcher setup and `exec` failures distinctly
2. Implement three independent demonstration policies. They are profiles, not
   cumulative layers: selecting `no-network` does not also select
   `compute-only`, and selecting `read-only-fs` does not select either one.
   This keeps each profile's behavior easy to explain and test.
   - `compute-only`: deny directory mutation, networking, and process-creation calls
   - `no-network`: deny common socket, connection, and message calls only
   - `read-only-fs`: deny common filesystem mutation calls only
   A future combined profile could deliberately union these deny lists, but it
   is not needed for this teaching prototype.
3. Add two small sample programs per policy:
   - compute-only: one permitted computation and one directory-creation attempt
   - no-network: one harmless program and one socket attempt
   - read-only-fs: one file read and one directory-creation attempt
4. Update the Makefile for all launcher and sample binaries, with `clean` support.
5. Rewrite the README for Ubuntu under WSL 2 with installation, build, run, and
   expected-result commands.
6. Reduce `sysjail_project_proposal.md` to a concise project brief. Keep the
   important boundary that seccomp filters syscalls but does not provide full
   filesystem or network isolation; keep implementation details in this plan.

## Validation

Run these commands inside Ubuntu/WSL 2 after installing the dependencies:

```sh
make clean
make
./sysjail --policy compute-only -- ./compute_allowed
./sysjail --policy compute-only -- ./compute_file_attempt
./sysjail --policy no-network -- ./network_allowed
./sysjail --policy no-network -- ./network_attempt
./sysjail --policy read-only-fs -- ./filesystem_read
./sysjail --policy read-only-fs -- ./filesystem_mutation
```

The allowed samples should exit successfully. The restricted operations should
fail with `EPERM` and the samples should report that failure. Tests must be run
on Linux because libseccomp and seccomp are Linux kernel interfaces.

For an external target such as `curl`, any denial message is formatted by
`curl` after one of its syscalls is rejected. The exact message depends on the
policy and the first syscall `curl` reaches; `compute-only` may block a thread
creation step before networking. SysJail prints the policy/target line and
returns the target status; it does not rewrite the target's stderr or identify
every denied syscall after the fact.

## Out of Scope

- namespaces, chroot, mount isolation, capabilities, or resource limits
- complete filesystem read-only enforcement
- complete network isolation
- syscall logging or a `SIGSYS` reporting framework
- support for non-Linux hosts
