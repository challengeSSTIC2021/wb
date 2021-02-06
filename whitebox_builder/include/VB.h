#ifndef VB_H
#define VB_H


extern unsigned char Table[] __attribute__((visibility("hidden")));
extern const unsigned TableSize __attribute__((visibility("hidden")));

__attribute__((visibility("default"))) int useVM(const unsigned char* input, unsigned char* output);
__attribute__((visibility("default"))) int getSuffix(unsigned char* output);
__attribute__((visibility("default"))) int getIdent(unsigned char* output);
__attribute__((visibility("hidden"))) int sheduleKey(const unsigned char* input, unsigned char* output);
__attribute__((visibility("hidden"))) int encrypt(const unsigned char* message, const unsigned char* context, unsigned char* output);
__attribute__((visibility("hidden"))) int decrypt(const unsigned char* message, const unsigned char* context, unsigned char* output);

#endif
