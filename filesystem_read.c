#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int file_descriptor = open("/etc/hostname", O_RDONLY);
    if (file_descriptor < 0)
    {
        perror("[target] filesystem read: open");
        return 1;
    }

    char buffer[128];
    ssize_t bytes_read = read(file_descriptor, buffer, sizeof(buffer) - 1);
    close(file_descriptor);
    if (bytes_read < 0)
    {
        perror("[target] filesystem read: read");
        return 1;
    }

    buffer[bytes_read] = '\0';
    printf("[target] filesystem read: %s", buffer);
    return 0;
}
