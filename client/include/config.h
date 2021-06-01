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
#ifndef CONFIG_H_
#define CONFIG_H_

#define STR_(name) #name
#define STR_NAME(name) STR_(name)

#define DEFAULT_BASE_URL "http://localhost:8080"

// WHITEBOX GEN API
#define AUTH_API_SUF "/api/auth.so"
#define GUEST_API_SUF "/api/guest.so"
#define FILES_API_SUF "/files/"
#define INDEX_JSON "index.json"

// WHITEBOX RELOAD TIMER
#define TIMEOUT_VM 3600

// KEY SERVER URL
#define DEFAULT_KEYSERVER_ADDRESS "127.0.0.1"
#define DEFAULT_KEYSERVER_PORT 1337

#define DEFAULT_KEYSERVER_PORT_STR STR_NAME(DEFAULT_KEYSERVER_PORT)

#include <stdbool.h>
#include <string.h>
#include <netdb.h>

#ifdef HTTP_WITH_VLC
#include <vlc_common.h>
#include <vlc_stream.h>
#include <vlc_threads.h>
#endif

#if 0
#define debug_printf(...) fprintf(__VA_ARGS__)
#else
#define debug_printf(...)
#endif

struct Context {
    char* keyserver_addr;
    char* keyserver_port;
    int keyserver_fd;

    char* base_addr;
    char* currentlogin;
    char* currentpassword;
    bool permcheck;

    void* libhandle;

    int (*useVM)(const unsigned char*, unsigned char*);
    int (*getPerms)(unsigned char*);
    int (*getIdent)(unsigned char*);

#ifdef HTTP_WITH_VLC
    stream_t* vlc_obj;
    vlc_mutex_t read_mutex;
    bool stop_download;
#endif
};

void initContext(struct Context* ctx, char* base_url, char* key_server_url, char* key_server_port);
void setContext(struct Context* ctx, char* base_url, char* key_server_url, char* key_server_port);
void freeContext(struct Context* ctx);


#endif
