#ifndef MEDIA_CLIENT_H_
#define MEDIA_CLIENT_H_

#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "key-client.h"
#include "macro.h"

typedef enum {
    MEDIA_OK = 0,
    MEDIA_EMPTY = 1,
    MEDIA_UNKNOW = 2, // remote unkwnon (key not found or http_code != 200)
    MEDIA_WRONG_PERMS = 3,  // key server permission too low
    MEDIA_DEBUG_DEVICE = 4, // the key server is a debug server and cannot provide production key
    MEDIA_VM_PERM_FAIL = 5, // fail to load WB (permission error)
    MEDIA_VM_ERROR = 6,
    MEDIA_JSON_ERROR = 7,
    MEDIA_PATH_INVALID = 8,
    MEDIA_UNEXPECTED_ERROR = 9
} MediaResp;

struct MediaDir;

struct MediaFile {
    char* name;
    char* remote_name;
    uint64_t perm;
    char* type;
    uint64_t ident;
    struct MediaDir* parent;
};

struct MediaDir {
    char* name;
    char* remote_name;
    uint64_t perm;
    uint64_t ident;
    struct MediaDir* parent;

    bool is_open;

    struct MediaDir* subdir;
    size_t nb_subdir;

    struct MediaFile* files;
    size_t nb_file;
};

NO_EXPORT MediaResp open_index(struct Context* ctx, struct MediaDir* index);
NO_EXPORT MediaResp open_dir(struct Context* ctx, struct MediaDir* dir);

// if *fd < 1, a temporary file will be allocate
NO_EXPORT MediaResp get_file_key(struct Context* ctx, uint64_t ident, unsigned char *key);
NO_EXPORT MediaResp download_file_with_key(struct Context* ctx, const char* remote_name, unsigned char *key, int* fd);
NO_EXPORT MediaResp download_file(struct Context* ctx, struct MediaFile* file, int* fd);

NO_EXPORT void close_dir(struct MediaDir* dir);
NO_EXPORT void close_index(struct MediaDir* index);

NO_EXPORT MediaResp get_file(struct Context* ctx, struct MediaDir* curdir, const char* path, struct MediaFile** file);
NO_EXPORT MediaResp get_dir(struct Context* ctx, struct MediaDir* curdir, const char* path, struct MediaDir** dir);
NO_EXPORT MediaResp get_dir_path(struct MediaDir* curdir, char** out);
NO_EXPORT MediaResp get_file_path(struct MediaFile* curfile, char** out);

//NO_EXPORT char** path_parse(const char* path);
//NO_EXPORT void free_path_parse(char** path);

#endif
