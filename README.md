# Phase 1: Seccomp syscall-filter proof of concept

This proof of concept follows Phase 1 of `OS_Project_Idea.md`. `sysjail`
installs a `libseccomp` filter in a child process before executing a target
program. The filter returns `EPERM` for `SYS_mkdir` and allows all other
syscalls. The target programs are ordinary programs and know nothing about
seccomp or the filter.

## Build

On Debian or Ubuntu (including WSL 2), install the development dependency:

```sh
sudo apt install build-essential libseccomp-dev
make
```

## Run

```sh
./sysjail ./blocked_mkdir
./sysjail ./allowed_program
```

`blocked_mkdir` attempts to create a directory and reports success only if the
ordinary `mkdir()` call succeeds. When run through `sysjail`, the kernel
rejects that call with `EPERM`, so the test exits with failure. `allowed_program`
does not call `mkdir` and reaches its success message normally. The launcher
uses the command-line arguments to choose which target to execute.
