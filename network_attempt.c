#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_descriptor < 0)
    {
        perror("[target] network attempt: socket");
        return 1;
    }

    close(socket_descriptor);
    puts("[target] network attempt: socket created");
    return 0;
}
