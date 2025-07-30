// gcc -o master master.c -pthread
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

char *global_buffer;

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}

void *thread_routine() {
    char buf[256];

    global_buffer = buf;
}

void read_bytes(char *buf, size_t size) {
    size_t sz = 0;
    size_t idx = 0;
    size_t tmp;

    while (sz < size) {
        tmp = read(0, &buf[idx], 1);
        if (tmp != 1) {
            exit(-1);
        }
        idx += 1;
        sz += 1;
    }
    return;
}

int main(int argc, char *argv[]) {
    size_t size = 0;
    pthread_t thread_t;
    int idx = 0;
    char leave_comment[32];

    initialize();

    while (1) {
        printf("1. Create thread\n");
        printf("2. Input\n");
        printf("3. Exit\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                if (pthread_create(&thread_t, NULL, thread_routine, NULL) < 0) {
                    perror("thread create error");
                    exit(0);
                }
                break;
            case 2:
                printf("Size: ");
                scanf("%lu", &size);

                printf("Data: ");
                read_bytes(global_buffer, size);

                printf("Data: %s", global_buffer);
                break;
            case 3:
                printf("Leave comment: ");
                read(0, leave_comment, 1024);
                return 0;
            default:
                printf("Nope\n");
                break;
        }
    }

    return 0;
}
