#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

int main(void)
{
    const char *directory = "sysjail_demo_directory";
    if (mkdir(directory, 0700) < 0)
    {
        perror("[target] filesystem mutation: mkdir");
        return 1;
    }

    printf("[target] filesystem mutation: created %s\n", directory);
    return 0;
}
