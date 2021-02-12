#ifndef MEDIA_CLIENT_H_
#define MEDIA_CLIENT_H_

#include <stdbool.h>
#include <stdint.h>

#include "key-client.h"

typedef enum {
    MEDIA_OK = 0,
    MEDIA_EMPTY = 1,
    MEDIA_UNKNOW = 2, // remote unkwnon (key not found or http_code != 200)
    MEDIA_WRONG_PERMS = 3,  // key server permission too low
    MEDIA_VM_PERM_FAIL = 4, // fail to load WB (permission error)
    MEDIA_VM_ERROR = 5,
    MEDIA_JSON_ERROR = 6,
    MEDIA_PATH_INVALID = 7,
    MEDIA_UNEXPECTED_ERROR = 8
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

MediaResp open_index(struct MediaDir* index);
MediaResp open_dir(struct MediaDir* dir);

// if *fd < 1, a temporary file will be allocate
MediaResp download_file(struct MediaFile* file, int* fd);

void close_dir(struct MediaDir* dir);
void close_index(struct MediaDir* index);

MediaResp get_file(struct MediaDir* curdir, const char* path, struct MediaFile** file);
MediaResp get_dir(struct MediaDir* curdir, const char* path, struct MediaDir** dir);
MediaResp get_dir_path(struct MediaDir* curdir, char** out);

//char** path_parse(const char* path);
//void free_path_parse(char** path);

#endif
