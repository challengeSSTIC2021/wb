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

static KeyResp send_recv_(struct Context* ctx, const char* in, size_t in_size, char* out, size_t *out_size) {
    if (ctx == NULL || out == NULL || *out_size < 1) {
        return RESP_INTERNAL_ERROR;
    }

    if (ctx->keyserver_fd <= -1) {
        struct addrinfo hints = {0};
        struct addrinfo *result, *rp;
        ctx->keyserver_fd = -1;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_PASSIVE;

        int s = getaddrinfo(ctx->keyserver_addr, ctx->keyserver_port, &hints, &result);
        if (s != 0) {
            debug_printf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
            debug_printf(stderr, "%s %s\n", ctx->keyserver_addr, ctx->keyserver_port);
            return RESP_CONNECTION_ERROR;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            ctx->keyserver_fd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);
            if (ctx->keyserver_fd == -1) {
                continue;
            }

            if (connect(ctx->keyserver_fd, rp->ai_addr, rp->ai_addrlen) != -1) {
                break;
            }

            close(ctx->keyserver_fd);
            ctx->keyserver_fd = -1;
        }

        if (rp == NULL || ctx->keyserver_fd == -1) {
            freeaddrinfo(result);
            debug_printf(stderr, "Could not connect\n");
            return RESP_CONNECTION_ERROR;
        }

        freeaddrinfo(result);

        char header[4] = {0};
        s = recv(ctx->keyserver_fd, header, sizeof(header), MSG_WAITALL);
        if (s != sizeof(header) || strncmp(header, "STIC", sizeof(header)) != 0) {
            close(ctx->keyserver_fd);
            ctx->keyserver_fd = -1;
            return RESP_CONNECTION_ERROR;
        }
    }

    int s = send(ctx->keyserver_fd, in, in_size, 0);
    if (s != in_size) {
        close(ctx->keyserver_fd);
        ctx->keyserver_fd = -1;
        return RESP_INTERNAL_ERROR;
    }
    s = recv(ctx->keyserver_fd, out, 1, MSG_WAITALL);

    size_t l = KeyResp_len(out[0]);
    if (l == 0 || *out_size < l) {
        close(ctx->keyserver_fd);
        ctx->keyserver_fd = -1;
        return RESP_INTERNAL_ERROR;
    }

    if (l > 1) {
        s = recv(ctx->keyserver_fd, out + 1, *out_size - 1, MSG_WAITALL);
        if (s <= 0) {
            close(ctx->keyserver_fd);
            ctx->keyserver_fd = -1;
            return RESP_INTERNAL_ERROR;
        }
    }

    *out_size = l;
    return out[0];
}

static KeyResp send_recv(struct Context* ctx, const char* in, size_t in_size, char* out, size_t *out_size) {
    if (ctx == NULL) {
        return RESP_INTERNAL_ERROR;
    }
    // if a connection is already opened, a error may occured if the server close the connexion. Retry with a new connexion
    if (ctx->keyserver_fd > -1) {
        KeyResp r = send_recv_(ctx, in, in_size, out, out_size);
        if (r != RESP_INTERNAL_ERROR) {
            return r;
        }
        if (ctx->keyserver_fd > -1) {
            close(ctx->keyserver_fd);
        }
        ctx->keyserver_fd = -1;
    }
    return send_recv_(ctx, in, in_size, out, out_size);
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
        debug_printf(stderr, "send_recv return %u\n", r);
        return r;
    } else {
        debug_printf(stderr, "send_recv return %u\n", r);
        return RESP_INTERNAL_ERROR;
    }
}

KeyResp getkey(struct Context* ctx, struct vmsign* payload, unsigned char* key) {
    char in_msg[1 + sizeof(struct vmsign)] = {0};
    char out_msg[1 + 16] = {0};
    size_t out_msg_size = sizeof(out_msg);

    in_msg[0] = REQ_GETKEY;
    memcpy(&in_msg[1], payload->data, sizeof(payload->data));
    memcpy(&in_msg[1 + sizeof(payload->data)], payload->ident, sizeof(payload->ident));

    KeyResp r = send_recv(ctx, in_msg, sizeof(in_msg), out_msg, &out_msg_size);
    if (r == RESP_GETKEY_OK && out_msg_size == sizeof(out_msg)) {
        memcpy(key, &out_msg[1], 16);
        return r;
    } else if (r == RESP_GETKEY_EXPIRED || r == RESP_GETKEY_INVALID_PERMS || r == RESP_GETKEY_UNKNOW || r == RESP_GETKEY_DEBUG_DEVICE || r >= RESP_ERROR_CODE) {
        debug_printf(stderr, "send_recv return %u\n", r);
        return r;
    } else {
        debug_printf(stderr, "send_recv return %u\n", r);
        return RESP_INTERNAL_ERROR;
    }
}

