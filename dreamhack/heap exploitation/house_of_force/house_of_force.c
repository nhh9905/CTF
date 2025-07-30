// gcc -o force force.c -m32 -mpreferred-stack-boundary=2
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

int *ptr[10];

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

int create(int cnt) {
	int size;

	if( cnt > 10 ) {
		return 0;
	}

	printf("Size: ");
	scanf("%d", &size);

	ptr[cnt] = malloc(size);

	if(!ptr[cnt]) {
		return -1;
	}

	printf("Data: ");
	read(0, ptr[cnt], size);

	printf("%p: %s\n", ptr[cnt], ptr[cnt]);
	return 0;
}

int write_ptr() {
	int idx;
	int w_idx;
	unsigned int value;

	printf("ptr idx: ");
	scanf("%d", &idx);

	if(idx > 10 || idx < 0) {
		return -1;
	} 

	printf("write idx: ");
	scanf("%d", &w_idx);

	if(w_idx > 100 || w_idx < 0) {
		return -1;
	}
	printf("value: ");
	scanf("%u", &value);

	ptr[idx][w_idx] = value;

	return 0;
}

void get_shell() {
	system("/bin/sh");
}
int main() {
	int idx;
	int cnt = 0;
	int w_cnt = 0;
	initialize();

	while(1) {
		printf("1. Create\n");
		printf("2. Write\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);

		switch(idx) {
			case 1:
				create(cnt++);
				cnt++;
				break;
			case 2:
				if(w_cnt) {
					return -1;
				}
				write_ptr();
				w_cnt++;
				break;
			case 3:
				exit(0);
			default:
				break;
		}
	}

	return 0;
}