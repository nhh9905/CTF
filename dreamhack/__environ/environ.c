// Name: environ.c
// Compile: gcc -o environ environ.c

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sig_handle() {
  exit(0);
}
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  signal(SIGALRM, sig_handle);
  alarm(5);
}

void read_file() {
  char file_buf[4096];

  int fd = open("./flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);
  close(fd);
}
int main() {
  char buf[1024];
  long addr;
  int idx;

  init();
  read_file();

  printf("stdout: %p\n", stdout);

  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("Addr: ");
        scanf("%ld", &addr);
        printf("%s", (char *)addr);
        break;
      default:
        break;
    }
  }
  return 0;
}
