#ifndef KEY_CLIENT_H_
#define KEY_CLIENT_H_

#include "wb_loader.h"
#include "macro.h"
#include "config.h"

typedef enum {
    REQ_CHECK = 0,
    REQ_GETKEY = 1,
} KeyReq;

typedef enum {
    RESP_ACK = 0,
    RESP_CHECK_OK = 1,
    RESP_CHECK_EXPIRED = 2,
    RESP_GETKEY_OK = 3,
    RESP_GETKEY_EXPIRED = 4,
    RESP_GETKEY_INVALID_PERMS = 5,
    RESP_GETKEY_UNKNOW = 6,
    RESP_ERROR_CODE = 0xf0,
    RESP_REQUEST_ERROR = 0xfe,
    RESP_UNEXPECTED_ERROR = 0xff,
    RESP_INTERNAL_ERROR = 0xffffffff,
} KeyResp;

NO_EXPORT KeyResp check_hsign(struct Context* ctx, struct vmsign* payload, unsigned char* plain);
NO_EXPORT KeyResp getkey(struct Context* ctx, struct vmsign* payload, unsigned char* key, unsigned char* counter);

#endif
