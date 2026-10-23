#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(void)
{
    if (mkdir("test_directory", 0700) < 0)
    {
        perror("mkdir");
        return EXIT_FAILURE;
    }

    printf("[SUCCESS] mkdir created test_directory.\n");
    return EXIT_SUCCESS;
}
