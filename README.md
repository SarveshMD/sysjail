# SysJail

SysJail is a small Linux syscall-filtering launcher written in C. It uses
libseccomp to install a policy in a child process and then runs the requested
program with `execvp()`.

This project targets Ubuntu running in WSL 2. It demonstrates seccomp; it is
not a complete sandbox. It does not isolate the filesystem or network, close
already-open file descriptors, or protect against every form of hostile code.

## Install and build

Run these commands inside Ubuntu/WSL 2:

```sh
sudo apt update
sudo apt install build-essential libseccomp-dev
make clean
make
```

## Usage

```sh
./sysjail --policy <compute-only|no-network|read-only-fs> -- <program> [args...]
```

The `--` separator is required. SysJail prints the selected policy and the
complete target command before starting it:

```text
[sysjail] applying policy 'read-only-fs'
[sysjail] starting target: mkdir dummydir
```

Messages beginning with `[sysjail]` come from the launcher. The executed
program owns its own output. The included sample programs mark their messages
with `[target]`; external programs such as `curl` will use their normal output
format.

After the target finishes, SysJail prints its exit status. The launcher returns
the target's exit code, or `128 + signal` when the target is terminated by a
signal. The target's own stderr remains unmodified, so a line such as
`mkdir: cannot create directory ...` is from `mkdir`, not SysJail.

## Policy profiles

The profiles are independent demonstrations, not layers applied on top of one
another. Each starts from an allow-by-default seccomp filter and adds its own
deny list:

| Profile | Denies | Does not automatically deny |
| --- | --- | --- |
| `compute-only` | directory mutation, common networking, and process creation | ordinary file reads and unrelated filesystem calls |
| `no-network` | common socket creation, connection, listening, and message calls | directory mutation and process creation |
| `read-only-fs` | common filesystem mutation such as `mkdir`, `unlink`, `rename`, and `truncate` | all networking and every possible filesystem write path |

`compute-only` is not a general "most restrictive" mode, and `no-network` is
not a layer over it. If a future assignment needs a combined policy, it should
be named explicitly and deliberately union the relevant deny lists. Keeping
these profiles independent makes each demonstration's effect predictable.

## Demonstrations

```sh
./sysjail --policy compute-only -- ./compute_allowed
./sysjail --policy compute-only -- ./compute_file_attempt
./sysjail --policy no-network -- ./network_allowed
./sysjail --policy no-network -- ./network_attempt
./sysjail --policy read-only-fs -- ./filesystem_read
./sysjail --policy read-only-fs -- ./filesystem_mutation
```

The permitted examples exit successfully. Restricted samples print an
`[target]` error ending in `Operation not permitted` and return failure.

## Why curl prints the error

Try:

```sh
./sysjail --policy no-network -- curl -I https://example.com
```

The first line is from SysJail. Any later error is from `curl`: the kernel
returns an error such as `EPERM` to `curl` when a filtered syscall is denied,
and `curl` formats the message. The exact message depends on which syscall it
reaches first. For example, `compute-only` also blocks process/thread creation,
so `curl` may fail while starting its resolver before it attempts a socket.
SysJail does not intercept or rewrite the target's stderr, and an `EPERM`
filter result does not by itself tell the parent which program printed the
message. SysJail reports setup failures and the target's final exit status
separately.

## Limitations

Seccomp filters syscall numbers and selected metadata. It generally cannot tell
whether a file descriptor points to a regular file, terminal, pipe, or socket.
The `read-only-fs` name describes a demonstration deny list, not complete
read-only filesystem isolation. Stronger isolation requires additional Linux
controls such as namespaces, mount restrictions, capabilities, and resource
limits.

## Files

- `sysjail.c`: launcher and policy implementation
- `*_allowed.c`, `*_attempt.c`, `filesystem_read.c`, and
  `filesystem_mutation.c`: demonstration targets
- `PLAN.md`: implementation roadmap and validation checklist
