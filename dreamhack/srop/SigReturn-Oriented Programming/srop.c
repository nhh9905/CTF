// Name: srop.c
// Compile: gcc -o srop srop.c -fno-stack-protector -no-pie

#include <unistd.h>

int gadget() {
  asm("pop %rax;"
      "syscall;"
      "ret" );
}

int main()
{
  char buf[16];
  read(0, buf ,1024);
}
