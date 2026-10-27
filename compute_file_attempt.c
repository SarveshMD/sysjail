#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

int main(void)
{
    if (mkdir("compute_demo_directory", 0700) < 0)
    {
        perror("[target] compute restricted attempt: mkdir");
        return 1;
    }

    printf("[target] compute restricted attempt: directory created\n");
    return 0;
}
