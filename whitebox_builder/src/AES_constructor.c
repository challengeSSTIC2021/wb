
#include "AESKEY.h"
#include "VB.h"
#include "crypto_stream.h"

__attribute__((constructor)) void initAESTable() {
  unsigned char nonce[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  crypto_stream_aes128ctr_xor(Table, Table, TableSize, nonce, AESKey);
}
