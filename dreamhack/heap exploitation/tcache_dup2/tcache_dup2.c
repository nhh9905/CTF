#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[7];

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void create_heap(int idx) {
    size_t size;

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    ptr[idx] = malloc(size);

    if (!ptr[idx])
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size-1);
}

void modify_heap() {
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap() {
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}
int main() {
    int idx;
    int i = 0;

    initialize();

    while (1) {
        printf("1. Create heap\n");
        printf("2. Modify heap\n");
        printf("3. Delete heap\n");
        printf("> ");

        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create_heap(i);
                i++;
                break;
            case 2:
                modify_heap();
                break;
            case 3:
                delete_heap();
                break;
            default:
                break;
        }
    }
}
