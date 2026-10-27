#include <stdio.h>

int main(void)
{
    unsigned long long total = 0;

    for (unsigned int value = 1; value <= 100; ++value)
    {
        total += (unsigned long long)value * value;
    }

    printf("[target] compute allowed: sum of squares = %llu\n", total);
    return 0;
}
