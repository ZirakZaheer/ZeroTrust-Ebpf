
#include <stdio.h>
#include <stdint.h>

int main() {
   uint64_t big = 4467389980;
   uint16_t small = big & 0xFFFF;
   printf("small is %u/n", small);
   return 0;
	
}

