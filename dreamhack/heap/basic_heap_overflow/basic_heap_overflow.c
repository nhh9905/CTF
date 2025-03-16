#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

struct over {
    void (*table)();
};

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell() {
    system("/bin/sh");
}

void table_func() {
    printf("overwrite_me!");
}

int main() {
    char *ptr = malloc(0x20);

    struct over *over = malloc(0x20);

    initialize();

    over->table = table_func;

    scanf("%s", ptr);

    if( !over->table ){
        return 0;
    }

    over->table();
    return 0;
}