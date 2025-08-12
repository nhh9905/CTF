//g++ -o cpp_string cpp_string.cpp
#include <iostream>
#include <fstream>
#include <csignal>
#include <unistd.h>
#include <stdlib.h>

char readbuffer[64] = {0, };
char flag[64] = {0, };
std::string writebuffer;

void alarm_handler(int trash)
{
    std::cout << "TIME OUT" << std::endl;
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int read_file(){
	std::ifstream is ("test", std::ifstream::binary);
	if(is.is_open()){
        	is.read(readbuffer, sizeof(readbuffer));
		is.close();

		std::cout << "Read complete!" << std::endl;
        	return 0;
	}
	else{
        	std::cout << "No testfile...exiting.." << std::endl;
        	exit(0);
	}
}

int write_file(){
	std::ofstream of ("test", std::ifstream::binary);
	if(of.is_open()){
		std::cout << "Enter file contents : ";
        	std::cin >> writebuffer;
		of.write(writebuffer.c_str(), sizeof(readbuffer));
                of.close();
		std::cout << "Write complete!" << std::endl;
        	return 0;
	}
	else{
		std::cout << "Open error!" << std::endl;
		exit(0);
	}
}

int read_flag(){
        std::ifstream is ("flag", std::ifstream::binary);
        if(is.is_open()){
                is.read(flag, sizeof(readbuffer));
                is.close();
                return 0;
        }
        else{
		std::cout << "You must need flagfile.." << std::endl;
                exit(0);
        }
}

int show_contents(){
	std::cout << "contents : ";
	std::cout << readbuffer << std::endl;
	return 0;
}
	


int main(void) {
    initialize();
    int selector = 0;
    while(1){
    	std::cout << "Simple file system" << std::endl;
    	std::cout << "1. read file" << std::endl;
    	std::cout << "2. write file" << std::endl;
	std::cout << "3. show contents" << std::endl;
    	std::cout << "4. quit" << std::endl;
    	std::cout << "[*] input : ";
	std::cin >> selector;
	
	switch(selector){
		case 1:
			read_flag();
			read_file();
			break;
		case 2:
			write_file();
			break;
		case 3:
			show_contents();
			break;
		case 4:
			std::cout << "BYEBYE" << std::endl;
			exit(0);
	}
    }
}
