// g++ -o pwn-container-overflow-1 pwn-container-overflow-1.cpp -no-pie

#include <iostream>
#include <vector>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <cstdio>

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

void print_menu(){
	std::cout << "container system!" << std::endl;
	std::cout << "1. make container" << std::endl;
	std::cout << "2. modify container" << std::endl;
	std::cout << "3. copy container" << std::endl;
	std::cout << "4. view container" << std::endl;
	std::cout << "5. exit system" << std::endl;
	std::cout << "[*] select menu: ";
}

class Menu{
public:
	Menu(){
	}
	Menu(const Menu&){
	}
	void (*fp)(void) = print_menu;
};


void getshell(){
	system("/bin/sh");
}

void make_container(std::vector<int> &src, std::vector<int> &dest){
	std::cout << "Input container1 data" << std::endl;
	int data = 0;
	for(std::vector<int>::iterator iter = src.begin(); iter != src.end(); iter++){
		std::cout << "input: ";
		std::cin >> data;
		*iter = data;
	}
	std::cout << std::endl;

	std::cout << "Input container2 data" << std::endl;
	for(std::vector<int>::iterator iter = dest.begin(); iter != dest.end(); iter++){
		std::cout << "input: ";
		std::cin >> data;
		*iter = data;
	}
	std::cout << std::endl;
}

void modify_container(std::vector<int> &src, std::vector<int> &dest){
	int size = 0;

	std::cout << "Input container1 size" << std::endl;
	std::cin >> size;
	src.resize(size);

	std::cout << "Input container2 size" << std::endl;
	std::cin >> size;
	dest.resize(size);
}

void copy_container(std::vector<int> &src, std::vector<int> &dest){
	std::copy(src.begin(), src.end(), dest.begin());
	std::cout << "copy complete!" << std::endl;
}

void view_container(std::vector<int> &src, std::vector<int> &dest){
	std::cout << "container1 data: [";
	for(std::vector<int>::iterator iter = src.begin(); iter != src.end(); iter++){
		std::cout << *iter << ", ";
	}
	std::cout << "]" << "\n" << std::endl;

	std::cout << "container2 data: [";
	for(std::vector<int>::iterator iter = dest.begin(); iter != dest.end(); iter++){
		std::cout << *iter << ", ";
	}
	std::cout << "]" << "\n" << std::endl;
}


int main(){
	initialize();
	std::vector<int> src(3, 0);
	std::vector<int> dest(3, 0);
	Menu *menu = new Menu();
	int selector = 0;
	
	while(1){
		menu->fp();
		std::cin >> selector;
		switch(selector){
			case 1:
				make_container(src, dest);
				break;
			case 2:
				modify_container(src, dest);
				break;
			case 3:
				copy_container(src, dest);
				break;
			case 4:
				view_container(src, dest);
				break;
			case 5:
				return 0;
				break;
			default:
				break;
		}
	}
}