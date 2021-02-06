
#include <curl/curl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wb_loader.h"

#define BASE_URL "http://127.0.0.1:8080/"
#define AUTH_API BASE_URL "api/auth.so"
#define GUEST_API BASE_URL "api/guest.so"

#define TIMEOUT_VM  1000

struct {
    char* currentlogin;
    char* currentpassword;

    void* libhandle;

    int (*useVM)(const unsigned char*, unsigned char*);
    int (*getSuffix)(unsigned char*);
    int (*getIdent)(unsigned char*);
} internal_state;

static VMError close_state() {
    if (internal_state.libhandle == NULL) {
        return VM_OK;
    }

    dlclose(internal_state.libhandle);
    internal_state.libhandle = NULL;
    internal_state.useVM = NULL;
    internal_state.getSuffix = NULL;
    internal_state.getIdent = NULL;

    return VM_OK;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    int fd = *((int*) userdata);
    return write(fd, ptr, size*nmemb);
}

static VMError open_state() {
    if (internal_state.libhandle != NULL) {
        return VM_OK;
    }
    char path[] = "/tmp/libVMXXXXXX.so";
    int fd = mkstemps(path, 3);

    if (fd == -1) {
        return VM_INTERNAL_ERROR;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return VM_INTERNAL_ERROR;
    }
    if (curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd) != CURLE_OK ) goto curlError;

    if (internal_state.currentlogin != NULL && internal_state.currentpassword != NULL) {
        if (curl_easy_setopt(curl, CURLOPT_URL, AUTH_API) != CURLE_OK ) goto curlError;
        if (curl_easy_setopt(curl, CURLOPT_USERNAME, internal_state.currentlogin) != CURLE_OK ) goto curlError;
        if (curl_easy_setopt(curl, CURLOPT_PASSWORD, internal_state.currentpassword) != CURLE_OK ) goto curlError;
    } else {
        if (curl_easy_setopt(curl, CURLOPT_URL, GUEST_API) != CURLE_OK ) goto curlError;
    }

    if (curl_easy_perform(curl) != CURLE_OK ) goto curlError;
    close(fd);

    long http_code = 0;
    if (curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK ) goto curlError;
    if (http_code != 200) {
        curl_easy_cleanup(curl);
        unlink(path);
        if (http_code == 401) {
            return VM_AUTH_FAIL;
        } else {
            return VM_INTERNAL_ERROR;
        }
    }

    curl_easy_cleanup(curl);

    chmod(path, 0700);

    internal_state.libhandle = dlopen(path, RTLD_LOCAL | RTLD_LAZY);

    unlink(path);

    if (internal_state.libhandle == NULL) {
        return VM_INTERNAL_ERROR;
    }

    internal_state.useVM = (int (*)(const unsigned char*, unsigned char*)) dlsym(internal_state.libhandle, "useVM");
    internal_state.getSuffix = (int (*)(unsigned char*)) dlsym(internal_state.libhandle, "getSuffix");
    internal_state.getIdent = (int (*)(unsigned char*)) dlsym(internal_state.libhandle, "getIdent");

    if (internal_state.useVM == NULL || internal_state.getSuffix == NULL || internal_state.getIdent == NULL) {
        close_state();
        return VM_INTERNAL_ERROR;
    }

    return VM_OK;

curlError:
    curl_easy_cleanup(curl);
    close(fd);
    unlink(path);
    return VM_INTERNAL_ERROR;
}

static int reopen_state() {
    if (internal_state.libhandle != NULL) {
        close_state();
    }
    return open_state();
}

VMError remote_login(const char* username, const char* password) {
    if (username == NULL || password == NULL) {
        return remote_logout();
    }
    if (internal_state.libhandle != NULL) {
        if (internal_state.currentlogin != NULL || internal_state.currentpassword != NULL) {
            if (strcmp(internal_state.currentlogin, username) == 0 &&
                strcmp(internal_state.currentpassword, password) == 0) {
                return VM_OK;
            }
        }
        close_state();
    }
    if (internal_state.currentlogin != NULL) free(internal_state.currentlogin);
    if (internal_state.currentpassword != NULL) free(internal_state.currentpassword);
    internal_state.currentlogin = strdup(username);
    internal_state.currentpassword = strdup(password);

    return open_state();
}

VMError remote_logout() {
    if (internal_state.currentlogin != NULL || internal_state.currentpassword != NULL) {
        close_state();
        if (internal_state.currentlogin != NULL) free(internal_state.currentlogin);
        if (internal_state.currentpassword != NULL) free(internal_state.currentpassword);
        internal_state.currentlogin = NULL;
        internal_state.currentpassword = NULL;
    }
    return VM_OK;
}

uint64_t get_current_permission() {
    if (internal_state.getSuffix == NULL) {
        VMError res = open_state();
        if (res != VM_OK) {
            abort();
        }
    }

    uint64_t res;
    internal_state.getSuffix( (unsigned char*) &res);
    return res;
}

VMError hsign(uint64_t toSign, struct vmsign* out) {
    if (internal_state.getSuffix == NULL || internal_state.getIdent == NULL || internal_state.useVM == NULL) {
        VMError res = open_state();
        if (res != VM_OK) {
            return res;
        }
    }
    internal_state.getIdent((unsigned char*) out->ident);
    unsigned long VM_ts = *((uint32_t*) out->ident);
    unsigned long current_ts = time(NULL);

    if (VM_ts + TIMEOUT_VM < current_ts) {
        VMError res = reopen_state();
        if (res != VM_OK) {
            return res;
        }
        internal_state.getIdent((unsigned char*) out->ident);
        VM_ts = *((uint32_t*) out->ident);
        current_ts = time(NULL);
        if (VM_ts + TIMEOUT_VM < current_ts) {
            return VM_INTERNAL_ERROR;
        }
    }

    unsigned char b[16];
    *( (uint64_t*) &b) = toSign;
    internal_state.getSuffix(&b[8]);

    int t = internal_state.useVM(b, (unsigned char*) out->data);
    if (t != 0) {
        return VM_SIGN_FAIL;
    } else {
        return VM_OK;
    }
}

