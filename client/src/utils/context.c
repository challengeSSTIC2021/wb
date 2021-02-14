
#include <stdlib.h>


#include "config.h"
#include "wb_loader.h"

void freeContext(struct Context* ctx) {
    if (ctx == NULL) {
        return;
    }
    remote_logout(ctx);

    free(ctx->keyserver_addr);
    free(ctx->keyserver_port);
    free(ctx->addr_info.ai_addr);
    free(ctx->currentlogin);
    free(ctx->currentpassword);
    free(ctx->base_addr);
    memset(ctx, '\0', sizeof(struct Context));
    ctx->addr_info_init = false;
}

void initContext(struct Context* ctx, char* base_url, char* key_server_url, char* key_server_port) {
    if (ctx == NULL) {
        return;
    }

    memset(ctx, '\0', sizeof(struct Context));
    ctx->addr_info_init = false;

    setContext(ctx, base_url, key_server_url, key_server_port);
}

void setContext(struct Context* ctx, char* base_url, char* key_server_url, char* key_server_port) {
    if (ctx == NULL) {
        return;
    }

    if (base_url != NULL) {
        if (ctx->base_addr != NULL) {
            free(ctx->base_addr);
        }
        ctx->base_addr = strdup(base_url);
    } else if (ctx->base_addr == NULL) {
        ctx->base_addr = strdup(DEFAULT_BASE_URL);
    }

    bool reset_addr_info = false;
    if (key_server_url != NULL) {
        if (ctx->keyserver_addr == NULL || strcmp(key_server_url, ctx->keyserver_addr) != 0) {
            free(ctx->keyserver_addr);
            ctx->keyserver_addr = strdup(key_server_url);
            reset_addr_info = true;
        }
    } else if (ctx->keyserver_addr == NULL) {
        ctx->keyserver_addr = strdup(DEFAULT_KEYSERVER_ADDRESS);
        reset_addr_info = true;
    }

    if (key_server_port != NULL) {
        if (ctx->keyserver_port == NULL || strcmp(key_server_port, ctx->keyserver_port) != 0) {
            free(ctx->keyserver_port);
            ctx->keyserver_port = strdup(key_server_port);
            reset_addr_info = true;
        }
    } else if (ctx->keyserver_port == NULL) {
        ctx->keyserver_port = strdup(str(DEFAULT_KEYSERVER_PORT));
        reset_addr_info = true;
    }

    if (reset_addr_info && ctx->addr_info_init) {
        free(ctx->addr_info.ai_addr);
        ctx->addr_info_init = false;
    }
}
