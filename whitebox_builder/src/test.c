/*
 *  Copyright 2021 Nicolas Surbayrole
 *  Copyright 2021 Quarkslab
 *  Copyright 2021 Association STIC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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

  getPerms(&message[8]);

  printf("input: ");
  printHex(message, 16);

  useVM(message, out);

  printf("output: ");
  printHex(out, 16);
  return 0;
}
