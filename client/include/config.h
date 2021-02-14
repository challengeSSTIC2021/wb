#ifndef CONFIG_H_
#define CONFIG_H_

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
#define str(a) #a

#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HTTP_WITH_VLC
#include <vlc_common.h>
#endif


struct Context {
    char* keyserver_addr;
    char* keyserver_port;
    struct addrinfo addr_info;
    bool addr_info_init;

    char* base_addr;
    char* currentlogin;
    char* currentpassword;

    void* libhandle;

    int (*useVM)(const unsigned char*, unsigned char*);
    int (*getSuffix)(unsigned char*);
    int (*getIdent)(unsigned char*);

#ifdef HTTP_WITH_VLC
    vlc_object_t* vlc_obj;
#endif
};

void initContext(struct Context* ctx, char* base_url, char* key_server_url, char* key_server_port);
void setContext(struct Context* ctx, char* base_url, char* key_server_url, char* key_server_port);
void freeContext(struct Context* ctx);


#endif
