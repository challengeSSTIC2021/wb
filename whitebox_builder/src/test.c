
#include <stdio.h>
#include <stdlib.h>
#include "libwblib.h"

void printHex(unsigned char* msg, int size) {
  int i;
  for (i = 0; i<size; i++) {
    printf("%02x", msg[i]);
  }
  printf("\n");
}

int main() {

  unsigned char message[16] = {0};
  unsigned char out[16] = {0};

  getSuffix(&message[8]);

  printf("input: ");
  printHex(message, 16);

  useVM(message, out);

  printf("output: ");
  printHex(out, 16);
  return 0;
}
