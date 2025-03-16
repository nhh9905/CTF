#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

int main()
{

	char cmd_ip[256] = "ifconfig";
	int dummy;
	char center_name[24];

	init();

	printf("Center name: ");
	read(0, center_name, 100);


	if( !strncmp(cmd_ip, "ifconfig", 8)) {
		system(cmd_ip);
	}

	else {
		printf("Something is wrong!\n");
	}
	exit(0);
}
