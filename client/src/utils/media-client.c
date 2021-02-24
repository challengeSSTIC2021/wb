#define _GNU_SOURCE

#ifndef HTTP_WITH_VLC
#include <curl/curl.h>
#else
#include <vlc_common.h>
#include <vlc_access.h>
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gcrypt.h>

#include "cJSON.h"

#include "media-client.h"
#include "key-client.h"
#include "wb_loader.h"
#include "config.h"

struct write_data {
    int fd;
    bool decode;

#ifndef HTTP_WITH_VLC
    gcry_cipher_hd_t h;
    unsigned char buffer[16];
    size_t buffer_used;
#endif
};

static const unsigned char default_counter[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

#ifndef HTTP_WITH_VLC

static size_t decode_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    struct write_data* cb_data = (struct write_data*) userdata;
    if (cb_data->decode) {
        if (size*nmemb > CURL_MAX_WRITE_SIZE) {
            abort();
        }
        unsigned char tmp[CURL_MAX_WRITE_SIZE + 16];

        size_t real_size = size*nmemb + cb_data->buffer_used;
        size_t l_uncipher = real_size - (real_size % 16);

        memcpy(tmp, cb_data->buffer, cb_data->buffer_used);
        memcpy(tmp + cb_data->buffer_used, ptr, size*nmemb);

        memcpy(cb_data->buffer, tmp + l_uncipher, real_size % 16);
        cb_data->buffer_used = real_size % 16;

        if (gcry_cipher_decrypt(cb_data->h, tmp, l_uncipher, NULL, 0) != GPG_ERR_NO_ERROR) {
            return 0;
        }

        if (write(cb_data->fd, tmp, l_uncipher) == l_uncipher) {
            return size*nmemb;
        } else {
            return 0;
        }
    } else {
        return write(cb_data->fd, ptr, size*nmemb);
    }
}

static inline MediaResp download_media(struct Context* ctx, const char* name, unsigned char* key, struct write_data *cb_data) {
    if (key == NULL && cb_data->decode) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    char* url;
    if (asprintf(&url, "%s" FILES_API_SUF "%s", ctx->base_addr, name) == -1) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    if (cb_data->decode) {
        if (gcry_cipher_open(&cb_data->h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0) != GPG_ERR_NO_ERROR) {
            free(url);
            return MEDIA_UNEXPECTED_ERROR;
        }
        if (gcry_cipher_setkey(cb_data->h, key, 16) != GPG_ERR_NO_ERROR) {
            gcry_cipher_close(cb_data->h);
            free(url);
            return MEDIA_UNEXPECTED_ERROR;
        }
        if (gcry_cipher_setctr(cb_data->h, default_counter, 16) != GPG_ERR_NO_ERROR) {
            gcry_cipher_close(cb_data->h);
            free(url);
            return MEDIA_UNEXPECTED_ERROR;
        }
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        if (cb_data->decode) gcry_cipher_close(cb_data->h);
        free(url);
        return MEDIA_UNEXPECTED_ERROR;
    }
    if (curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, decode_write_callback) != CURLE_OK ) goto curlError;
    if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, cb_data) != CURLE_OK ) goto curlError;

    if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK ) goto curlError;

    if (curl_easy_perform(curl) != CURLE_OK ) goto curlError;

    long http_code = 0;
    if (curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK) goto curlError;

    free(url);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        if (cb_data->decode) gcry_cipher_close(cb_data->h);
        return MEDIA_UNKNOW;
    }

    if (cb_data->decode) {
        if (gcry_cipher_final(cb_data->h) != GPG_ERR_NO_ERROR) {
            gcry_cipher_close(cb_data->h);
            return MEDIA_UNEXPECTED_ERROR;
        }
        if (gcry_cipher_decrypt(cb_data->h, cb_data->buffer, cb_data->buffer_used, NULL, 0) != GPG_ERR_NO_ERROR) {
            gcry_cipher_close(cb_data->h);
            return MEDIA_UNEXPECTED_ERROR;
        }
        write(cb_data->fd, cb_data->buffer, cb_data->buffer_used);
        cb_data->buffer_used = 0;
        gcry_cipher_close(cb_data->h);
    }

    if (lseek(cb_data->fd, 0, SEEK_CUR) == 0) {
        return MEDIA_EMPTY;
    }

    return MEDIA_OK;

curlError:
    if (cb_data->decode) gcry_cipher_close(cb_data->h);
    curl_easy_cleanup(curl);
    free(url);
    return MEDIA_UNEXPECTED_ERROR;
}

#else

#define BLOCK_SIZE (1<<16)

static inline MediaResp download_media(struct Context* ctx, const char* name, unsigned char* key, struct write_data *cb_data) {
    gcry_cipher_hd_t h;
    if (key == NULL && cb_data->decode) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    char* url;
    if (asprintf(&url, "%s" FILES_API_SUF "%s", ctx->base_addr, name) == -1) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    if (cb_data->decode) {
        if (gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0) != GPG_ERR_NO_ERROR) {
            free(url);
            return MEDIA_UNEXPECTED_ERROR;
        }
        if (gcry_cipher_setkey(h, key, 16) != GPG_ERR_NO_ERROR) {
            gcry_cipher_close(h);
            free(url);
            return MEDIA_UNEXPECTED_ERROR;
        }
        if (gcry_cipher_setctr(h, default_counter, 16) != GPG_ERR_NO_ERROR) {
            gcry_cipher_close(h);
            free(url);
            return MEDIA_UNEXPECTED_ERROR;
        }
    }

    stream_t* stream = vlc_stream_NewURL(ctx->vlc_obj, url);

    unsigned char buffer[BLOCK_SIZE] = {0};
    size_t recv_size;
    bool stop = false;

    do {
        recv_size = vlc_stream_Read(stream, buffer, BLOCK_SIZE);
        if (recv_size != BLOCK_SIZE) {
            if (recv_size < 0 || !vlc_stream_Eof(stream)) {
                vlc_stream_Delete(stream);
                if (cb_data->decode) gcry_cipher_close(h);
                return MEDIA_UNEXPECTED_ERROR;
            }
            stop = true;
            if (cb_data->decode) {
                if (gcry_cipher_final(h) != GPG_ERR_NO_ERROR) {
                    vlc_stream_Delete(stream);
                    gcry_cipher_close(h);
                    return MEDIA_UNEXPECTED_ERROR;
                }
            }
        }
        if (cb_data->decode) {
            if (gcry_cipher_decrypt(h, buffer, recv_size, NULL, 0) != GPG_ERR_NO_ERROR) {
                vlc_stream_Delete(stream);
                gcry_cipher_close(h);
                return MEDIA_UNEXPECTED_ERROR;
            }
        }

        vlc_mutex_lock(&ctx->read_mutex);

        if(ctx->stop_download) {
            vlc_mutex_unlock(&ctx->read_mutex);
            vlc_stream_Delete(stream);
            if (cb_data->decode) gcry_cipher_close(h);
            return MEDIA_UNEXPECTED_ERROR;
        }

        write(cb_data->fd, buffer, recv_size);
        vlc_cond_broadcast(&ctx->read_cond);
        vlc_mutex_unlock(&ctx->read_mutex);
        usleep(10000);

    } while (!stop);

    vlc_stream_Delete(stream);
    if (cb_data->decode) {
        gcry_cipher_close(h);
    }

    if (lseek(cb_data->fd, 0, SEEK_CUR) == 0) {
        return MEDIA_EMPTY;
    }

    return MEDIA_OK;
}
#undef BLOCK_SIZE

#endif

static inline int create_tmp_file() {
    char filepath[] = "/tmp/MediaTmp-XXXXXX";
    int fd = mkstemp(filepath);
    if (fd < 0) {
        return -1;
    }
    unlink(filepath);
    return fd;
}

static inline MediaResp allocate_tmp_file(int fd, void** out, size_t* size) {
    off_t f_size = lseek(fd, 0, SEEK_END);
    *out = malloc(f_size);
    if (*out == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    lseek(fd, 0, SEEK_SET);
    *size = read(fd, *out, f_size);
    if (*size != f_size) {
        free(*out);
        *out = NULL;
        *size = 0;
        return MEDIA_UNEXPECTED_ERROR;
    }
    return MEDIA_OK;
}

static MediaResp download_root(struct Context* ctx, void** out, size_t* size) {
    int fd = create_tmp_file();
    if (fd < 0) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    struct write_data cb_data = {0};
    cb_data.fd = fd;
    cb_data.decode = false;
    MediaResp r = download_media(ctx, INDEX_JSON, NULL, &cb_data);
    if (r != MEDIA_OK) {
        close(fd);
        return r;
    }
    r = allocate_tmp_file(fd, out, size);
    close(fd);
    return r;
}

NO_EXPORT MediaResp get_file_key(struct Context* ctx, uint64_t ident, unsigned char *key) {
    int retry = 2;
    KeyResp rkey;

    do {
        retry--;
        struct vmsign token;
        VMError rvm = hsign(ctx, ident, &token);
        if (rvm != VM_OK) {
            if (rvm == VM_AUTH_FAIL) {
                return MEDIA_VM_PERM_FAIL;
            } else {
                return MEDIA_VM_ERROR;
            }
        }

        rkey = getkey(ctx, &token, key);
        if (rkey != RESP_GETKEY_EXPIRED) {
            retry = -1;
        } else {
            rvm = relogin(ctx);
            if (rvm != VM_OK) {
                if (rvm == VM_AUTH_FAIL) {
                    return MEDIA_VM_PERM_FAIL;
                } else {
                    return MEDIA_VM_ERROR;
                }
           }
        }
    } while (retry >= 0);

    if (rkey != RESP_GETKEY_OK) {
        if (rkey == RESP_GETKEY_INVALID_PERMS) {
            return MEDIA_WRONG_PERMS;
        } else if (rkey == RESP_GETKEY_UNKNOW) {
            return MEDIA_UNKNOW;
        } else if (rkey == RESP_GETKEY_DEBUG_DEVICE) {
            return MEDIA_DEBUG_DEVICE;
        } else {
            fprintf(stderr, "Unexpected %d\n", rkey);
            return MEDIA_UNEXPECTED_ERROR;
        }
    }
    return MEDIA_OK;
}

NO_EXPORT MediaResp download_file_with_key(struct Context* ctx, const char* remote_name, unsigned char *key, int* fd) {
    struct write_data cb_data = {0};
    cb_data.decode = true;

    if (*fd < 1) {
        *fd = create_tmp_file();
        if (*fd < 0) {
            return MEDIA_UNEXPECTED_ERROR;
        }
        cb_data.fd = *fd;

        MediaResp r = download_media(ctx, remote_name, key, &cb_data);
        if (r != MEDIA_OK) {
            close(*fd);
            *fd = -1;
        }
        return r;
    } else {
        cb_data.fd = *fd;
        return download_media(ctx, remote_name, key, &cb_data);
    }
}

static MediaResp download_ident(struct Context* ctx, const char* name, uint64_t ident, int* fd) {
    unsigned char key[16] = {0};

    MediaResp r = get_file_key(ctx, ident, key);
    if (r != MEDIA_OK) {
        return r;
    }
    return download_file_with_key(ctx, name, key, fd);
}

static void erase_file(struct MediaFile* file) {
    if (file == NULL) {
        return;
    }
    if (file->name != NULL) free(file->name);
    if (file->remote_name != NULL) free(file->remote_name);
    if (file->type != NULL) free(file->type);

    file->name = NULL;
    file->remote_name = NULL;
    file->type = NULL;
    file->parent = NULL;
}

static void erase_dir(struct MediaDir* dir) {
    if (dir == NULL) {
        return;
    }
    close_dir(dir);

    if (dir->name != NULL) free(dir->name);
    if (dir->remote_name != NULL) free(dir->remote_name);

    dir->name = NULL;
    dir->remote_name = NULL;
    dir->parent = NULL;
}

void close_dir(struct MediaDir* dir) {
    if (dir == NULL || dir->is_open == false) {
        return;
    }

    if (dir->files != NULL) {
        for (int i = 0; i<dir->nb_file; i++) {
            erase_file(&dir->files[i]);
        }
        free(dir->files);
        dir->files = NULL;
        dir->nb_file = 0;
    }

    if (dir->subdir != NULL) {
        for (int i = 0; i<dir->nb_subdir; i++) {
            erase_dir(&dir->subdir[i]);
        }
        free(dir->subdir);
        dir->subdir = NULL;
        dir->nb_subdir = 0;
    }

    dir->is_open = false;
}

void close_index(struct MediaDir* index) {
    if (index == NULL) {
        return;
    }
    erase_dir(index);
}

MediaResp download_file(struct Context* ctx, struct MediaFile* file, int* fd) {
    if (file == NULL || fd == NULL || ctx == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    uint64_t current_perm = get_current_permission(ctx);
    if (current_perm > file->perm) {
        return MEDIA_WRONG_PERMS;
    }

    return download_ident(ctx, file->remote_name, file->ident, fd);
}

static inline bool is64bitsHexString(const char* v) {
    char* endptr = NULL;
    strtoull(v, &endptr, 16);
    // all the string is valid, and 16 hexa char has been process
    return endptr != NULL && *endptr == 0 && endptr == &v[16];
}

static inline uint64_t get64bitsHexString(const char* v) {
    return strtoull(v, NULL, 16);
}

static MediaResp parse_json_index(void* json_str, size_t json_size, struct MediaDir* dest) {

    const cJSON *el = NULL;
    cJSON *json = cJSON_ParseWithLength(json_str, json_size);
    if (json == NULL) {
        return MEDIA_JSON_ERROR;
    }

    size_t nb_file = 0;
    size_t nb_dir = 0;

    // check json format
    if (! cJSON_IsArray(json)) goto json_error;

    cJSON_ArrayForEach(el, json) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(el, "name");
        cJSON *real_name = cJSON_GetObjectItemCaseSensitive(el, "real_name");
        cJSON *type = cJSON_GetObjectItemCaseSensitive(el, "type");
        cJSON *ident = cJSON_GetObjectItemCaseSensitive(el, "ident");
        cJSON *perms = cJSON_GetObjectItemCaseSensitive(el, "perms");

        if (! (cJSON_IsString(ident) && cJSON_IsString(perms) && cJSON_IsString(type) && cJSON_IsString(name) && cJSON_IsString(real_name) &&
               ident->valuestring != NULL && perms->valuestring != NULL && type->valuestring != NULL && name->valuestring != NULL && real_name->valuestring != NULL &&
               is64bitsHexString(ident->valuestring) && is64bitsHexString(perms->valuestring))) {
            goto json_error;
        }

        if (strcmp(type->valuestring, "dir_index") == 0) {
            nb_dir++;
        } else {
            nb_file++;
        }
    }
    dest->is_open = true;

    if (nb_dir == 0) {
        dest->nb_subdir = 0;
        dest->subdir = NULL;
    } else {
        dest->subdir = malloc(nb_dir * sizeof(struct MediaDir));
        if (dest->subdir == NULL) {
            close_dir(dest);
            cJSON_Delete(json);
            return MEDIA_UNEXPECTED_ERROR;
        }
        dest->nb_subdir = nb_dir;
        memset(dest->subdir, 0, nb_dir * sizeof(struct MediaDir));
        for (int i=0; i<nb_dir; i++) {
            dest->subdir[i].is_open = false;
        }
    }

    if (nb_file == 0) {
        dest->nb_file = 0;
        dest->files = NULL;
    } else {
        dest->files = malloc(nb_file * sizeof(struct MediaFile));
        if (dest->files == NULL) {
            close_dir(dest);
            cJSON_Delete(json);
            return MEDIA_UNEXPECTED_ERROR;
        }
        dest->nb_file = nb_file;
        memset(dest->files, 0, nb_file * sizeof(struct MediaFile));
    }

    size_t i_file = 0;
    size_t i_dir = 0;

    cJSON_ArrayForEach(el, json) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(el, "name");
        cJSON *real_name = cJSON_GetObjectItemCaseSensitive(el, "real_name");
        cJSON *type = cJSON_GetObjectItemCaseSensitive(el, "type");
        cJSON *ident = cJSON_GetObjectItemCaseSensitive(el, "ident");
        cJSON *perms = cJSON_GetObjectItemCaseSensitive(el, "perms");

        if (strcmp(type->valuestring, "dir_index") == 0) {
            struct MediaDir* curDir = &dest->subdir[i_dir];
            i_dir++;

            curDir->remote_name = strdup(name->valuestring);
            curDir->name = strdup(real_name->valuestring);
            curDir->perm = get64bitsHexString(perms->valuestring);
            curDir->ident = get64bitsHexString(ident->valuestring);
            curDir->parent = dest;

            if (curDir->remote_name == NULL || curDir->name == NULL) {
                close_dir(dest);
                cJSON_Delete(json);
                return MEDIA_UNEXPECTED_ERROR;
            }
        } else {
            struct MediaFile* curFile = &dest->files[i_file];
            i_file++;

            curFile->remote_name = strdup(name->valuestring);
            curFile->name = strdup(real_name->valuestring);
            curFile->type = strdup(type->valuestring);
            curFile->perm = get64bitsHexString(perms->valuestring);
            curFile->ident = get64bitsHexString(ident->valuestring);
            curFile->parent = dest;

            if (curFile->remote_name == NULL || curFile->name == NULL || curFile->type == NULL) {
                close_dir(dest);
                cJSON_Delete(json);
                return MEDIA_UNEXPECTED_ERROR;
            }
        }
    }

    cJSON_Delete(json);
    return MEDIA_OK;


json_error:
    cJSON_Delete(json);
    return MEDIA_JSON_ERROR;
}

MediaResp open_index(struct Context* ctx, struct MediaDir* index) {
    if (ctx == NULL || index == NULL || index->name != NULL || index->remote_name != NULL || index->parent != NULL ||
            index->subdir != NULL || index->files != NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    void* json = NULL;
    size_t json_size = 0;
    MediaResp r = download_root(ctx, &json, &json_size);
    if (r != MEDIA_OK || json == NULL) {
        if (json != NULL) {
            free(json);
        }
        return r;
    }
    index->is_open = false;
    index->parent = NULL;
    index->perm = 0xffffffffffffffff;
    index->remote_name = NULL;
    index->name = NULL;

    r = parse_json_index(json, json_size, index);
    free(json);
    return r;
}

MediaResp open_dir(struct Context* ctx, struct MediaDir* dir) {
    if (dir == NULL || ctx == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    if (dir->is_open) {
        return MEDIA_OK;
    }
    if (dir->name == NULL || dir->remote_name == NULL || dir->parent == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }

    uint64_t current_perm = get_current_permission(ctx);
    if (current_perm > dir->perm) {
        return MEDIA_WRONG_PERMS;
    }

    int fd = 0;
    MediaResp r = download_ident(ctx, dir->remote_name, dir->ident, &fd);
    if (r != MEDIA_OK) {
        return r;
    }

    void* json = NULL;
    size_t json_size = 0;
    r = allocate_tmp_file(fd, &json, &json_size);
    close(fd);
    if (r != MEDIA_OK || json == NULL) {
        if (json != NULL) {
            free(json);
        }
        return r;
    }

    r = parse_json_index(json, json_size, dir);
    free(json);

    return r;
}

static inline MediaResp get_dir_path_(struct MediaDir* curdir, char** out, size_t l) {
    if (curdir == NULL || out == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    if (curdir->parent == NULL) {
        if (*out != NULL) {
            free(*out);
        }
        *out = malloc(2 + l);
        if (*out == NULL) {
            return MEDIA_UNEXPECTED_ERROR;
        }
        memset(*out, '\0', 2+l);
        strcpy(*out, "/");
    } else {
        if (curdir->name == NULL) {
            return MEDIA_UNEXPECTED_ERROR;
        }
        const size_t name_len = strlen(curdir->name);
        MediaResp r = get_dir_path_(curdir->parent, out, l + 1 + name_len);
        if (r != MEDIA_OK) {
            return r;
        }
        if (*out == NULL) {
            return MEDIA_UNEXPECTED_ERROR;
        }
        strncat(*out, curdir->name, name_len);
        strcat(*out, "/");
    }
    return MEDIA_OK;
}

MediaResp get_dir_path(struct MediaDir* curdir, char** out) {
    return get_dir_path_(curdir, out, 0);
}

MediaResp get_file_path(struct MediaFile* curfile, char** out) {
    if (curfile == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    const size_t l = strlen(curfile->name);
    MediaResp r = get_dir_path_(curfile->parent, out, l);
    if (r != MEDIA_OK) {
        return r;
    }
    if (*out == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    strncat(*out, curfile->name, l);
    return MEDIA_OK;
}

static inline char* alloc_next_path(const char *path, const char** out) {
    size_t current_size = 16;
    char* arg = malloc(16);
    size_t current_index = 0;
    if (arg == NULL) {
        return NULL;
    }
    char c;
    bool stop = false;
    size_t path_index = 0;
    do {
        c = path[path_index];

        if (c == '\0' || c == EOF || c == '?') {
            stop = true;
        } else if (c == '/') {
            if (current_index != 0) {
                stop = true;
            }
            path_index++;
        } else {
            arg[current_index] = c;
            current_index++;
            path_index++;
        }
        if (current_index >= current_size) {
            current_size = current_size + 16;
            arg = realloc(arg, current_size);
            if (arg == NULL) {
                return NULL;
            }
        }
    } while (!stop);

    arg[current_index] = '\0';
    if (out != NULL) {
        *out = &path[path_index];
    }

    return arg;
}

static inline char** path_parse(const char* path) {
    if (path == NULL) {
        return NULL;
    }
    size_t max_element = 4;
    char** path_list = malloc(sizeof(char*) * max_element);
    if (path_list == NULL) {
        return NULL;
    }
    size_t current_element = 0;

    const char* current_position = path;
    const char* next_position = NULL;

    if (*current_position == '/') {
        path_list[current_element] = malloc(2);
        if (path_list[current_element] == NULL) {
            free(path_list);
            return NULL;
        }
        strncpy(path_list[current_element], "/", 2);
        current_element++;
    }
    path_list[current_element] = NULL;

    while (*current_position != '\0' && *current_position != '?') {
        if (current_element + 1 >= max_element) {
            max_element += 4;
            path_list = realloc(path_list, sizeof(char*) * max_element);
            if (path_list == NULL) {
                return NULL;
            }
        }
        char* next_path = alloc_next_path(current_position, &next_position);
        if (next_path == NULL) {
            return NULL;
        }
        if (*next_path == '\0' || strcmp(next_path, ".") == 0) {
            free(next_path);
        } else if (strcmp(next_path, "..") == 0 && current_element > 0 &&
                strcmp(path_list[current_element-1], "..") != 0) {

            if (strcmp(path_list[current_element-1], "/") == 0) {
                free(next_path);
            } else {
                current_element--;
                free(next_path);
                free(path_list[current_element]);
                path_list[current_element] = NULL;
            }
        } else {
            path_list[current_element] = next_path;
            current_element++;
            path_list[current_element] = NULL;
        }
        current_position = next_position;
    }
    return path_list;
}

static inline void free_path_parse(char** path) {
    if (path == NULL) {
        return;
    }
    char** tmp = path;
    while(*tmp != NULL) {
        free(*tmp);
        *tmp = NULL;
        tmp++;
    }
    free(path);
}

MediaResp get_dir(struct Context* ctx, struct MediaDir* basedir, const char* path, struct MediaDir** outdir) {
    if (path == NULL || basedir == NULL || ctx == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    char** path_list = path_parse(path);
    if (path_list == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    char** cur_path = path_list;
    struct MediaDir* curdir = basedir;
    if (*cur_path != NULL && strcmp(*cur_path, "/") == 0) {
        while (curdir->parent != NULL) {
            curdir = curdir->parent;
        }
        cur_path++;
    }

    while (*cur_path != NULL) {
        MediaResp r = open_dir(ctx, curdir);
        if (r != MEDIA_OK) {
            free_path_parse(path_list);
            return r;
        }
        if (strcmp(*cur_path, ".") == 0) {
        } else if (strcmp(*cur_path, "..") == 0) {
            if (curdir->parent != NULL) {
                curdir = curdir->parent;
            }
        } else {
            bool found = false;
            for (size_t i = 0; i < curdir->nb_subdir; i++) {
                if (strcmp(*cur_path, curdir->subdir[i].name) == 0) {
                    curdir = &curdir->subdir[i];
                    found = true;
                    break;
                }
            }
            if (!found) {
                free_path_parse(path_list);
                return MEDIA_PATH_INVALID;
            }
        }
        cur_path++;
    }

    MediaResp r = open_dir(ctx, curdir);
    if (r != MEDIA_OK) {
        free_path_parse(path_list);
        return r;
    }

    if (outdir != NULL) {
        *outdir = curdir;
    }
    free_path_parse(path_list);
    return MEDIA_OK;
}

MediaResp get_file(struct Context* ctx, struct MediaDir* basedir, const char* path, struct MediaFile** outfile) {
    if (path == NULL || basedir == NULL || ctx == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    char** path_list = path_parse(path);
    if (path_list == NULL) {
        return MEDIA_UNEXPECTED_ERROR;
    }
    char** cur_path = path_list;
    struct MediaDir* curdir = basedir;
    if (*cur_path != NULL && strcmp(*cur_path, "/") == 0) {
        while (curdir->parent != NULL) {
            curdir = curdir->parent;
        }
        cur_path++;
    }

    while (*cur_path != NULL) {
        MediaResp r = open_dir(ctx, curdir);
        if (r != MEDIA_OK) {
            free_path_parse(path_list);
            return r;
        }
        if (strcmp(*cur_path, ".") == 0) {
        } else if (strcmp(*cur_path, "..") == 0) {
            if (curdir->parent != NULL) {
                curdir = curdir->parent;
            }
        } else if (*(cur_path + 1) == NULL) {
            for (size_t i = 0; i < curdir->nb_file; i++) {
                if (strcmp(*cur_path, curdir->files[i].name) == 0) {
                    if (outfile != NULL) {
                        *outfile = &curdir->files[i];
                    }
                    free_path_parse(path_list);
                    return MEDIA_OK;
                }
            }
            free_path_parse(path_list);
            return MEDIA_PATH_INVALID;
        } else {
            bool found = false;
            for (size_t i = 0; i < curdir->nb_subdir; i++) {
                if (strcmp(*cur_path, curdir->subdir[i].name) == 0) {
                    curdir = &curdir->subdir[i];
                    found = true;
                    break;
                }
            }
            if (!found) {
                free_path_parse(path_list);
                return MEDIA_PATH_INVALID;
            }
        }
        cur_path++;
    }

    free_path_parse(path_list);
    return MEDIA_PATH_INVALID;
}
