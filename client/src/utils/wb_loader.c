#define _GNU_SOURCE
#ifndef HTTP_WITH_VLC
#include <curl/curl.h>
#else
#include <vlc_common.h>
#include <vlc_access.h>
#include <vlc_url.h>
#endif
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wb_loader.h"
#include "key-client.h"
#include "config.h"

static inline VMError hsign_raw(struct Context* ctx, uint64_t toSign, struct vmsign* out) {
    if (ctx->getSuffix == NULL || ctx->getIdent == NULL || ctx->useVM == NULL) {
        return VM_INTERNAL_ERROR;
    }
    ctx->getIdent((unsigned char*) out->ident);

    unsigned char b[16];
    *( (uint64_t*) &b) = toSign;
    ctx->getSuffix(&b[8]);

    int t = ctx->useVM(b, (unsigned char*) out->data);
    if (t != 0) {
        return VM_SIGN_FAIL;
    } else {
        return VM_OK;
    }
}

static VMError close_state(struct Context* ctx) {
    if (ctx->libhandle == NULL) {
        return VM_OK;
    }

    dlclose(ctx->libhandle);
    ctx->libhandle = NULL;
    ctx->useVM = NULL;
    ctx->getSuffix = NULL;
    ctx->getIdent = NULL;

    return VM_OK;
}

#ifndef HTTP_WITH_VLC

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    int fd = *((int*) userdata);
    return write(fd, ptr, size*nmemb);
}

static inline VMError open_state_internal(struct Context* ctx) {
    if (ctx->libhandle != NULL) {
        return VM_OK;
    }
    char* url;
    if (ctx->currentlogin != NULL && ctx->currentpassword != NULL) {
        if (asprintf(&url, "%s" AUTH_API_SUF, ctx->base_addr) == -1) {
            return VM_INTERNAL_ERROR;
        }
    } else {
        if (asprintf(&url, "%s" GUEST_API_SUF, ctx->base_addr) == -1) {
            return VM_INTERNAL_ERROR;
        }
    }

    char path[] = "/tmp/libVMXXXXXX.so";
    int fd = mkstemps(path, 3);

    if (fd == -1) {
        free(url);
        return VM_INTERNAL_ERROR;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        free(url);
        return VM_INTERNAL_ERROR;
    }
    if (curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd) != CURLE_OK ) goto curlError;

    if (ctx->currentlogin != NULL && ctx->currentpassword != NULL) {
        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK ) goto curlError;
        if (curl_easy_setopt(curl, CURLOPT_USERNAME, ctx->currentlogin) != CURLE_OK ) goto curlError;
        if (curl_easy_setopt(curl, CURLOPT_PASSWORD, ctx->currentpassword) != CURLE_OK ) goto curlError;
    } else {
        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK ) goto curlError;
    }

    if (curl_easy_perform(curl) != CURLE_OK ) goto curlError;
    close(fd);

    long http_code = 0;
    if (curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK ) goto curlError;
    if (http_code != 200) {
        curl_easy_cleanup(curl);
        free(url);
        unlink(path);
        if (http_code == 401) {
            return VM_AUTH_FAIL;
        } else {
            return VM_INTERNAL_ERROR;
        }
    }

    curl_easy_cleanup(curl);
    free(url);

    chmod(path, 0700);

    ctx->libhandle = dlopen(path, RTLD_LOCAL | RTLD_LAZY);

    unlink(path);

    if (ctx->libhandle == NULL) {
        return VM_INTERNAL_ERROR;
    }

    ctx->useVM = (int (*)(const unsigned char*, unsigned char*)) dlsym(ctx->libhandle, "useVM");
    ctx->getSuffix = (int (*)(unsigned char*)) dlsym(ctx->libhandle, "getSuffix");
    ctx->getIdent = (int (*)(unsigned char*)) dlsym(ctx->libhandle, "getIdent");

    if (ctx->useVM == NULL || ctx->getSuffix == NULL || ctx->getIdent == NULL) {
        close_state(ctx);
        return VM_INTERNAL_ERROR;
    }

    return VM_OK;

curlError:
    curl_easy_cleanup(curl);
    close(fd);
    unlink(path);
    free(url);
    return VM_INTERNAL_ERROR;
}

#else

static inline VMError open_state_internal(struct Context* ctx) {
    if (ctx->libhandle != NULL) {
        return VM_OK;
    }
    char* url;
    if (ctx->currentlogin == NULL || ctx->currentpassword == NULL) {
        if (asprintf(&url, "%s" GUEST_API_SUF, ctx->base_addr) == -1) {
            return VM_INTERNAL_ERROR;
        }
    } else {
        struct vlc_url_t url_desc;
        if (vlc_UrlParse(&url_desc, ctx->base_addr) == -1) {
            vlc_UrlClean(&url_desc);
            return VM_INTERNAL_ERROR;
        }

        if (url_desc.i_port == 0){
            if (asprintf(&url, "%s://%s:%s@%s/%s" AUTH_API_SUF,
                        url_desc.psz_protocol,
                        ctx->currentlogin,
                        ctx->currentpassword,
                        url_desc.psz_host,
                        (url_desc.psz_path!=NULL)?url_desc.psz_path:"") == -1) {
                vlc_UrlClean(&url_desc);
                return VM_INTERNAL_ERROR;
            }
        } else {
            if (asprintf(&url, "%s://%s:%s@%s:%d/%s" AUTH_API_SUF,
                        url_desc.psz_protocol,
                        ctx->currentlogin,
                        ctx->currentpassword,
                        url_desc.psz_host,
                        url_desc.i_port,
                        (url_desc.psz_path!=NULL)?url_desc.psz_path:"") == -1) {
                vlc_UrlClean(&url_desc);
                return VM_INTERNAL_ERROR;
            }
        }
        vlc_UrlClean(&url_desc);
    }

    char path[] = "/tmp/libVMXXXXXX.so";
    int fd = mkstemps(path, 3);

    if (fd == -1) {
        free(url);
        return VM_INTERNAL_ERROR;
    }

    stream_t* stream = vlc_stream_NewURL(ctx->vlc_sd, url);
    if (stream == NULL) {
        close(fd);
        free(url);
        unlink(path);
        return VM_INTERNAL_ERROR;
    }

    const size_t block_size = 65536;
    unsigned char buffer[block_size] = {0};
    size_t recv_size;

    do {
        recv_size = vlc_stream_ReadPartial(stream, buffer, block_size);
        if (recv_size < 0) {
            vlc_stream_Delete(stream);
            close(fd);
            free(url);
            unlink(path);
            return VM_INTERNAL_ERROR;
        }
        write(fd, buffer, recv_size);
    } while (recv_size == block_size || !vlc_stream_Eof(stream));

    vlc_stream_Delete(stream);
    close(fd);
    free(url);

    chmod(path, 0700);

    ctx->libhandle = dlopen(path, RTLD_LOCAL | RTLD_LAZY);

    unlink(path);

    if (ctx->libhandle == NULL) {
        return VM_INTERNAL_ERROR;
    }

    ctx->useVM = (int (*)(const unsigned char*, unsigned char*)) dlsym(ctx->libhandle, "useVM");
    ctx->getSuffix = (int (*)(unsigned char*)) dlsym(ctx->libhandle, "getSuffix");
    ctx->getIdent = (int (*)(unsigned char*)) dlsym(ctx->libhandle, "getIdent");

    if (ctx->useVM == NULL || ctx->getSuffix == NULL || ctx->getIdent == NULL) {
        close_state(ctx);
        return VM_INTERNAL_ERROR;
    }

    return VM_OK;
}
#endif

static VMError open_state(struct Context* ctx) {
    const int retry = 10;

    // retry and check load
    for (int i = 0; i < retry; i++) {
        VMError res = open_state_internal(ctx);
        if (res == VM_OK) {
            struct vmsign s = {0};
            unsigned char out[16] = {0};
            res = hsign_raw(ctx, 0, &s);
            if (res == VM_OK) {
                uint64_t suffix = get_current_permission(ctx);
                KeyResp r = check_hsign(ctx, &s, out);
                if (r == RESP_CHECK_OK && (*((uint64_t*) out) == 0) && (*((uint64_t*) &out[8]) == suffix)) {
                    return VM_OK;
                } else {
                    fprintf(stderr, "[%d] check_hsign return %d\n", i, r);
                }
            } else {
                fprintf(stderr, "[%d] hsign_raw return %d\n", i, res);
            }
        } else {
            close_state(ctx);
            return res;
        }
        close_state(ctx);
        if (i == retry - 1) {
            break;
        }
        sleep(1);
    }
    return VM_INTERNAL_ERROR;
}

static inline int reopen_state(struct Context* ctx) {
    if (ctx->libhandle != NULL) {
        close_state(ctx);
    }
    return open_state(ctx);
}

VMError remote_login(struct Context* ctx, const char* username, const char* password) {
    if (ctx == NULL) {
        return VM_INTERNAL_ERROR;
    }
    if (username == NULL || password == NULL) {
        if (ctx->currentlogin != NULL || ctx->currentpassword != NULL) {
            close_state(ctx);
            if (ctx->currentlogin != NULL) free(ctx->currentlogin);
            if (ctx->currentpassword != NULL) free(ctx->currentpassword);
            ctx->currentlogin = NULL;
            ctx->currentpassword = NULL;
        }
        if (ctx->libhandle == NULL) {
            return open_state(ctx);
        }
        return VM_OK;
    }
    if (ctx->libhandle != NULL) {
        if (ctx->currentlogin != NULL || ctx->currentpassword != NULL) {
            if (strcmp(ctx->currentlogin, username) == 0 &&
                strcmp(ctx->currentpassword, password) == 0) {
                return VM_OK;
            }
        }
        close_state(ctx);
    }
    if (ctx->currentlogin != NULL) free(ctx->currentlogin);
    if (ctx->currentpassword != NULL) free(ctx->currentpassword);
    ctx->currentlogin = strdup(username);
    ctx->currentpassword = strdup(password);

    return open_state(ctx);
}

VMError remote_logout(struct Context* ctx) {
    if (ctx == NULL) {
        return VM_INTERNAL_ERROR;
    }
    if (ctx->currentlogin != NULL || ctx->currentpassword != NULL) {
        close_state(ctx);
        if (ctx->currentlogin != NULL) free(ctx->currentlogin);
        if (ctx->currentpassword != NULL) free(ctx->currentpassword);
        ctx->currentlogin = NULL;
        ctx->currentpassword = NULL;
    }
    return VM_OK;
}

VMError relogin(struct Context* ctx) {
    return reopen_state(ctx);
}

uint64_t get_current_permission(struct Context* ctx) {
    if (ctx->getSuffix == NULL) {
        VMError res = open_state(ctx);
        if (res != VM_OK) {
            return 0xffffffffffffffff;
        }
    }

    uint64_t res;
    ctx->getSuffix( (unsigned char*) &res);
    return res;
}

VMError hsign(struct Context* ctx, uint64_t toSign, struct vmsign* out) {
    if (ctx == NULL) {
        return VM_INTERNAL_ERROR;
    }
    if (ctx->getSuffix == NULL || ctx->getIdent == NULL || ctx->useVM == NULL) {
        VMError res = open_state(ctx);
        if (res != VM_OK) {
            return res;
        }
    }
    VMError res = hsign_raw(ctx, toSign, out);
    if (res != VM_OK) {
        return res;
    }

    unsigned long VM_ts = *((uint32_t*) out->ident);
    unsigned long current_ts = time(NULL);

    if (VM_ts + TIMEOUT_VM < current_ts) {
        res = reopen_state(ctx);
        if (res != VM_OK) {
            return res;
        }
        res = hsign_raw(ctx, toSign, out);
        if (res != VM_OK) {
            return res;
        }
        VM_ts = *((uint32_t*) out->ident);
        if (VM_ts + TIMEOUT_VM < current_ts) {
            return VM_INTERNAL_ERROR;
        }
    }

    return VM_OK;
}

