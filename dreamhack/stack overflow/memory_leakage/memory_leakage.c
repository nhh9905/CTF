#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

FILE *fp;

struct my_page {
	char name[16];
	int age;
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

int main()
{
	struct my_page my_page;
	char flag_buf[56];
	int idx;

	memset(flag_buf, 0, sizeof(flag_buf));
	
	initialize();

	while(1) {
		printf("1. Join\n");
		printf("2. Print information\n");
		printf("3. GIVE ME FLAG!\n");
		printf("> ");
		scanf("%d", &idx);
		switch(idx) {
			case 1:
				printf("Name: ");
				read(0, my_page.name, sizeof(my_page.name));

				printf("Age: ");
				scanf("%d", &my_page.age);
				break;
			case 2:
				printf("Name: %s\n", my_page.name);
				printf("Age: %d\n", my_page.age);
				break;
			case 3:
				fp = fopen("/flag", "r");
				fread(flag_buf, 1, 56, fp);
				break;
			default:
				break;
		}
	}

}