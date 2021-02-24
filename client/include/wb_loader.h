#ifndef WB_LOADER_H
#define WB_LOADER_H

#include "config.h"
#include <dlfcn.h>
#include <stdint.h>
#include "macro.h"

typedef enum {
    VM_OK = 0,
    VM_SIGN_FAIL = 1,
    VM_AUTH_FAIL = 2,
    VM_CONNECTION_ERROR = 0xfe,
    VM_INTERNAL_ERROR = 0xff,
} VMError;

NO_EXPORT VMError remote_login(struct Context* ctx, const char* username, const char* password);
NO_EXPORT VMError remote_logout(struct Context* ctx);
NO_EXPORT VMError relogin(struct Context* ctx);

NO_EXPORT uint64_t get_current_permission(struct Context* ctx);

struct vmsign {
  uint8_t data[16];
  uint8_t ident[4];
};

NO_EXPORT VMError hsign(struct Context* ctx, uint64_t toSign, struct vmsign* out);

#endif
