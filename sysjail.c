#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct launch_error
{
    int stage;
    int error_number;
};

enum launch_stage
{
    STAGE_NO_NEW_PRIVS = 1,
    STAGE_FILTER,
    STAGE_EXEC
};

static int add_denied_syscall(scmp_filter_ctx context, int syscall_number,
                              const char *name)
{
    if (seccomp_rule_add(context, SCMP_ACT_ERRNO(EPERM), syscall_number, 0) < 0)
    {
        fprintf(stderr, "[sysjail] could not deny syscall %s\n", name);
        return -1;
    }

    return 0;
}

static int add_compute_only_rules(scmp_filter_ctx context)
{
    const int syscalls[] = {
        SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(unlink),
        SCMP_SYS(socket), SCMP_SYS(socketpair), SCMP_SYS(connect),
        SCMP_SYS(bind), SCMP_SYS(listen), SCMP_SYS(accept), SCMP_SYS(accept4),
        SCMP_SYS(fork), SCMP_SYS(vfork), SCMP_SYS(clone), SCMP_SYS(clone3)};
    const char *names[] = {
        "mkdir", "mkdirat", "unlink", "socket", "socketpair", "connect",
        "bind", "listen", "accept", "accept4", "fork", "vfork", "clone",
        "clone3"};
    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);

    for (size_t index = 0; index < count; ++index)
    {
        if (add_denied_syscall(context, syscalls[index], names[index]) < 0)
        {
            return -1;
        }
    }

    return 0;
}

static int add_no_network_rules(scmp_filter_ctx context)
{
    const int syscalls[] = {
        SCMP_SYS(socket), SCMP_SYS(socketpair), SCMP_SYS(connect),
        SCMP_SYS(bind), SCMP_SYS(listen), SCMP_SYS(accept), SCMP_SYS(accept4),
        SCMP_SYS(sendto), SCMP_SYS(sendmsg), SCMP_SYS(sendmmsg),
        SCMP_SYS(recvfrom), SCMP_SYS(recvmsg), SCMP_SYS(recvmmsg)};
    const char *names[] = {
        "socket", "socketpair", "connect", "bind", "listen", "accept",
        "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg",
        "recvmmsg"};
    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);

    for (size_t index = 0; index < count; ++index)
    {
        if (add_denied_syscall(context, syscalls[index], names[index]) < 0)
        {
            return -1;
        }
    }

    return 0;
}

static int add_read_only_rules(scmp_filter_ctx context)
{
    const int syscalls[] = {
        SCMP_SYS(unlink), SCMP_SYS(unlinkat), SCMP_SYS(rmdir),
        SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2),
        SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(chmod),
        SCMP_SYS(fchmod), SCMP_SYS(fchmodat), SCMP_SYS(chown),
        SCMP_SYS(fchown), SCMP_SYS(fchownat), SCMP_SYS(truncate),
        SCMP_SYS(ftruncate)};
    const char *names[] = {
        "unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2",
        "mkdir", "mkdirat", "chmod", "fchmod", "fchmodat", "chown",
        "fchown", "fchownat", "truncate", "ftruncate"};
    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);

    for (size_t index = 0; index < count; ++index)
    {
        if (add_denied_syscall(context, syscalls[index], names[index]) < 0)
        {
            return -1;
        }
    }

    return 0;
}

static int install_filter(const char *policy)
{
    scmp_filter_ctx context = seccomp_init(SCMP_ACT_ALLOW);
    if (context == NULL)
    {
        fprintf(stderr, "[sysjail] seccomp_init failed\n");
        return -1;
    }

    int result;
    if (strcmp(policy, "compute-only") == 0)
    {
        result = add_compute_only_rules(context);
    }
    else if (strcmp(policy, "no-network") == 0)
    {
        result = add_no_network_rules(context);
    }
    else
    {
        result = add_read_only_rules(context);
    }

    if (result < 0)
    {
        seccomp_release(context);
        return -1;
    }

    if (seccomp_load(context) < 0)
    {
        fprintf(stderr, "[sysjail] seccomp_load failed\n");
        seccomp_release(context);
        return -1;
    }

    seccomp_release(context);
    return 0;
}

static void report_child_error(int error_fd, int stage)
{
    struct launch_error error = {stage, errno};
    (void)write(error_fd, &error, sizeof(error));
}

static void print_usage(const char *program_name)
{
    fprintf(stderr,
            "[sysjail] usage: %s --policy <compute-only|no-network|read-only-fs> -- "
            "<program> [args...]\n",
            program_name);
}

static void print_target_command(int argument_count, char *arguments[])
{
    fputs("[sysjail] starting target:", stderr);
    for (int index = 0; index < argument_count; ++index)
    {
        fprintf(stderr, " %s", arguments[index]);
    }
    fputc('\n', stderr);
}

int main(int argc, char *argv[])
{
    if (argc < 5 || strcmp(argv[1], "--policy") != 0 ||
        strcmp(argv[3], "--") != 0 ||
        (strcmp(argv[2], "compute-only") != 0 &&
         strcmp(argv[2], "no-network") != 0 &&
         strcmp(argv[2], "read-only-fs") != 0))
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    int error_pipe[2];
    if (pipe(error_pipe) < 0)
    {
        perror("[sysjail] pipe");
        return EXIT_FAILURE;
    }

    if (fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC) < 0)
    {
        perror("[sysjail] fcntl");
        close(error_pipe[0]);
        close(error_pipe[1]);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[sysjail] applying policy '%s'\n", argv[2]);
    print_target_command(argc - 4, &argv[4]);

    pid_t child = fork();
    if (child < 0)
    {
        perror("[sysjail] fork");
        close(error_pipe[0]);
        close(error_pipe[1]);
        return EXIT_FAILURE;
    }

    if (child == 0)
    {
        close(error_pipe[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        {
            report_child_error(error_pipe[1], STAGE_NO_NEW_PRIVS);
            _exit(127);
        }
        if (install_filter(argv[2]) < 0)
        {
            report_child_error(error_pipe[1], STAGE_FILTER);
            _exit(127);
        }
        execvp(argv[4], &argv[4]);
        report_child_error(error_pipe[1], STAGE_EXEC);
        _exit(127);
    }

    close(error_pipe[1]);
    struct launch_error child_error;
    ssize_t bytes_read = read(error_pipe[0], &child_error, sizeof(child_error));
    close(error_pipe[0]);

    int status;
    if (waitpid(child, &status, 0) < 0)
    {
        perror("[sysjail] waitpid");
        return EXIT_FAILURE;
    }

    if (bytes_read == (ssize_t)sizeof(child_error))
    {
        const char *stage = child_error.stage == STAGE_EXEC ? "execvp" : child_error.stage == STAGE_FILTER ? "seccomp setup"
                                                                                                           : "PR_SET_NO_NEW_PRIVS";
        fprintf(stderr, "[sysjail] %s failed: %s\n", stage,
                strerror(child_error.error_number));
        return EXIT_FAILURE;
    }

    if (WIFEXITED(status))
    {
        fprintf(stderr, "[sysjail] target exited with status %d\n",
                WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status))
    {
        fprintf(stderr, "[sysjail] target terminated by signal %d.\n",
                WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }

    fprintf(stderr, "[sysjail] target ended unexpectedly.\n");
    return EXIT_FAILURE;
}
