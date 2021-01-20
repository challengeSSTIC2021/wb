#ifndef VB_H
#define VB_H

static const unsigned suffix_size = 8;
static const unsigned input_size = 16;
static const unsigned output_size = 16;

// return 0 on success, 1 on error
// input: 16 bytes to encrypt, the last 8 must be the suffix
// output: the cipher of the 16 bytes messages
int encryptVM(const unsigned char* input, unsigned char* output);

int getSuffix(unsigned char* suffix);

#endif
