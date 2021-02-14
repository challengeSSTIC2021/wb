
#include <dlfcn.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "key-client.h"
#include "config.h"

#define BUFF_SIZE 4096

//static struct addrinfo addr_info = {0};
//static bool addr_info_init = false;

static KeyResp send_recv(struct Context* ctx, const char* in, size_t in_size, char* out, size_t *out_size) {
    int fd = -1;
    if (ctx == NULL) {
        return RESP_INTERNAL_ERROR;
    }

    if (!ctx->addr_info_init) {
        struct addrinfo hints = {0};
        struct addrinfo *result, *rp;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_PASSIVE;

        int s = getaddrinfo(ctx->keyserver_addr, ctx->keyserver_port, &hints, &result);
        if (s != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
            return RESP_INTERNAL_ERROR;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);
            if (fd == -1) {
                continue;
            }

            if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
                break;
            }

            close(fd);
            fd = -1;
        }

        if (rp == NULL) {
            freeaddrinfo(result);
            fprintf(stderr, "Could not connect\n");
            return RESP_INTERNAL_ERROR;
        }

        ctx->addr_info.ai_addr = malloc(rp->ai_addrlen);
        if (ctx->addr_info.ai_addr == NULL) {
            freeaddrinfo(result);
            fprintf(stderr, "malloc error\n");
            return RESP_INTERNAL_ERROR;
        }
        memcpy(ctx->addr_info.ai_addr, rp->ai_addr, rp->ai_addrlen);
        ctx->addr_info.ai_family = rp->ai_family;
        ctx->addr_info.ai_socktype = rp->ai_socktype;
        ctx->addr_info.ai_protocol = rp->ai_protocol;
        ctx->addr_info.ai_addrlen = rp->ai_addrlen;

        freeaddrinfo(result);
        ctx->addr_info_init = true;
    } else {
        fd = socket(ctx->addr_info.ai_family, ctx->addr_info.ai_socktype, ctx->addr_info.ai_protocol);
        if (fd == -1) {
            fprintf(stderr, "socket error\n");
            return RESP_INTERNAL_ERROR;
        }

        if (connect(fd, ctx->addr_info.ai_addr, ctx->addr_info.ai_addrlen) == -1) {
            fprintf(stderr, "Could not connect\n");
            close(fd);
            return RESP_INTERNAL_ERROR;
        }
    }

    int s = send(fd, in, in_size, 0);
    if (s != in_size) {
        close(fd);
        return RESP_INTERNAL_ERROR;
    }

    s = recv(fd, out, *out_size, MSG_WAITALL);
    close(fd);
    if (s <= 0) {
        *out_size = 0;
        return RESP_INTERNAL_ERROR;
    }

    *out_size = s;
    return out[0];
}

KeyResp check_hsign(struct Context* ctx, struct vmsign* payload, unsigned char* plain) {
    char in_msg[1 + sizeof(struct vmsign)];
    char out_msg[17];
    size_t out_msg_size = sizeof(out_msg);

    in_msg[0] = REQ_CHECK;
    memcpy(&in_msg[1], payload->data, sizeof(payload->data));
    memcpy(&in_msg[1 + sizeof(payload->data)], payload->ident, sizeof(payload->ident));

    KeyResp r = send_recv(ctx, in_msg, sizeof(in_msg), out_msg, &out_msg_size);
    if ((r == RESP_CHECK_OK || r == RESP_CHECK_EXPIRED) && out_msg_size == sizeof(out_msg)) {
        memcpy(plain, &out_msg[1], 16);
        return r;
    } else if (r >= RESP_ERROR_CODE) {
        fprintf(stderr, "send_recv return %u\n", r);
        return r;
    } else {
        fprintf(stderr, "send_recv return %u\n", r);
        return RESP_INTERNAL_ERROR;
    }
}

KeyResp getkey(struct Context* ctx, struct vmsign* payload, unsigned char* key, unsigned char* counter) {
    char in_msg[1 + sizeof(struct vmsign)] = {0};
    char out_msg[1 + 16 + 16] = {0};
    size_t out_msg_size = sizeof(out_msg);

    in_msg[0] = REQ_GETKEY;
    memcpy(&in_msg[1], payload->data, sizeof(payload->data));
    memcpy(&in_msg[1 + sizeof(payload->data)], payload->ident, sizeof(payload->ident));

    KeyResp r = send_recv(ctx, in_msg, sizeof(in_msg), out_msg, &out_msg_size);
    if (r == RESP_GETKEY_OK && out_msg_size == sizeof(out_msg)) {
        memcpy(key, &out_msg[1], 16);
        memcpy(counter, &out_msg[17], 16);
        return r;
    } else if (r == RESP_GETKEY_EXPIRED || r == RESP_GETKEY_INVALID_PERMS || r == RESP_GETKEY_UNKNOW || r >= RESP_ERROR_CODE) {
        fprintf(stderr, "send_recv return %u\n", r);
        return r;
    } else {
        fprintf(stderr, "send_recv return %u\n", r);
        return RESP_INTERNAL_ERROR;
    }
}

