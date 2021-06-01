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
