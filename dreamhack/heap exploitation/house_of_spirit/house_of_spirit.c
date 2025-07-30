// gcc -o hos hos.c -fno-stack-protector -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
	execve("/bin/sh", NULL, NULL);
}

int main() {
	char name[32];
	int idx, i, size = 0;
	long addr = 0;

	initialize();
	memset(name, 0, sizeof(name));
	printf("name: ");
	read(0, name, sizeof(name)-1);

	printf("%p: %s\n", name, name);
	while(1) {
		printf("1. create\n");
		printf("2. delete\n");
		printf("3. exit\n");
		printf("> ");

		scanf("%d", &idx);

		switch(idx) {
			case 1:
				if(i > 10) {
					return -1;
				}
				printf("Size: ");
				scanf("%d", &size);

				ptr[i] = malloc(size);

				if(!ptr[i]) {
					return -1;
				}
				printf("Data: ");
				read(0, ptr[i], size);
				i++;
				break;
			case 2:
				printf("Addr: ");
				scanf("%ld", &addr);

				free(addr);
				break;
			case 3:
				return 0;
			default: 
				break;
		}
	}

	return 0;
}