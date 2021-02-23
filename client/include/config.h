#ifndef CONFIG_H_
#define CONFIG_H_

#define STR_(name) #name
#define STR_NAME(name) STR_(name)

#define DEFAULT_BASE_URL "http://127.0.0.1:8080"

// WHITEBOX GEN API
#define AUTH_API_SUF "/api/auth.so"
#define GUEST_API_SUF "/api/guest.so"
#define FILES_API_SUF "/files/"
#define INDEX_JSON "index.json"

// WHITEBOX RELOAD TIMER
#define TIMEOUT_VM 1000

// KEY SERVER URL
#define DEFAULT_KEYSERVER_ADDRESS "127.0.0.1"
#define DEFAULT_KEYSERVER_PORT 65430

#define DEFAULT_KEYSERVER_PORT_STR STR_NAME(DEFAULT_KEYSERVER_PORT)

#include <stdbool.h>
#include <string.h>
#include <netdb.h>

#ifdef HTTP_WITH_VLC
#include <vlc_common.h>
#include <vlc_stream.h>
#include <vlc_threads.h>
#endif


struct Context {
    char* keyserver_addr;
    char* keyserver_port;
    int keyserver_fd;

    char* base_addr;
    char* currentlogin;
    char* currentpassword;

    void* libhandle;

    int (*useVM)(const unsigned char*, unsigned char*);
    int (*getSuffix)(unsigned char*);
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
