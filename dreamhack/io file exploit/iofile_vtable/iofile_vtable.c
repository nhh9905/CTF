#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char name[8];
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
int main(int argc, char *argv[]) {
    int idx = 0;
    int sel;

    initialize();

    printf("what is your name: ");
    read(0, name, 8);
    while(1) {
        printf("1. print\n");
        printf("2. error\n");
        printf("3. read\n");
        printf("4. chance\n");
        printf("> ");

        scanf("%d", &sel);
        switch(sel) {
            case 1:
                printf("GOOD\n");
                break;
            case 2:
                fprintf(stderr, "ERROR\n");
                break;
            case 3:
                fgetc(stdin);
                break;
            case 4:
                printf("change: ");
                read(0, stderr + 1, 8);
                break;
            default:
                break;
            }
    }
    return 0;
}
