/* msnw.c
 * gcc -no-pie -fno-stack-protector -mpreferred-stack-boundary=8 msnw.c -o msnw
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEONG 0
#define NYANG 1

#define NOT_QUIT 1
#define QUIT 0

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

int Meong() {
    char buf[0x40];

    memset(buf, 0x00, 0x130);

    printf("meong 🐶: ");
    read(0, buf, 0x132); // buffer overflow

    if (buf[0] == 'q')
        return QUIT;
    return NOT_QUIT;
}

int Nyang() {
    char buf[0x40];

    printf("nyang 🐱: ");
    printf("%s", buf);

    return NOT_QUIT;
}

int Call(int animal) {
    return animal == MEONG ? Meong() : Nyang();
}

void Echo() {
    while (Call(MEONG)) Call(NYANG);
}

void Win() {
    execl("/bin/cat", "/bin/cat", "./flag", NULL);
}

int main(void) {
    Init();

    Echo();
    puts("nyang 🐱: goodbye!");

    return 0;
}