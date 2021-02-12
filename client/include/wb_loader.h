#ifndef WB_LOADER_H
#define WB_LOADER_H

#include <dlfcn.h>
#include <stdint.h>

typedef enum {
    VM_OK = 0,
    VM_SIGN_FAIL = 1,
    VM_AUTH_FAIL = 2,
    VM_INTERNAL_ERROR = 0xff,
} VMError;

VMError remote_login(const char* username, const char* password);
VMError remote_logout();
VMError relogin();

uint64_t get_current_permission();

struct vmsign {
  uint8_t data[16];
  uint8_t ident[4];
};

VMError hsign(uint64_t toSign, struct vmsign* out);

#endif
