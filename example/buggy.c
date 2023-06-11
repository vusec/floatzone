#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fill_buffer(char *buf){
	memset(buf, 0x41, 16);
}

char buggy(unsigned int idx) {
	char buf[16];
	fill_buffer(buf);
	return buf[idx];
}

int main(int argc, char **argv) {
	printf("%c\n", buggy(atoi(argv[1])));
}
