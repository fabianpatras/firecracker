#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define GIB (1024LL * 1024LL * 1024LL)
#define MALLOC_SIZE (4 * GIB)

#define NUMBER_OF_ELEMS (MALLOC_SIZE / sizeof(uint32_t))

#define PAGE_SIZE ((uint64_t)4096)

#define STEP (PAGE_SIZE / sizeof(uint32_t))

int main()
{
    printf("We are trying malloc(0x%llx);\n", MALLOC_SIZE);

    uint32_t *vector = malloc(MALLOC_SIZE);

    if (vector == NULL)
    {
        printf("malloc failed :(\n");
        return 1;
    }

    printf("malloc ok :ok_hand:\n");

    for (uint32_t i = 0; i < NUMBER_OF_ELEMS; i += STEP)
    {
        vector[i] = i;
    }

    printf("went throug the entire vector\n");

    return 0;
}
