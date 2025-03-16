// Name: chall.c
// Compile: gcc -fno-stack-protector -no-pie chall.c -o chall

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

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


void flag() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};
  execve(cmd, args, NULL);
}

int main(int argc, char *argv[]) {
    int stdin_fd = 0;
    int stdout_fd = 1;
    char fruit[0x6] = "cherry";
    int buf_size = 0x10;
    char buf[0x6];

    initialize();

    write(stdout_fd, "Menu: ", 6);
    read(stdin_fd, buf, buf_size);
    if(!strncmp(buf, "cherry", 6)) {
        write(stdout_fd, "Is it cherry?: ", 15);
        read(stdin_fd, fruit, buf_size);
    }

    return 0;
}